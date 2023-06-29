from flask_restx import marshal
from datetime import datetime
from app import db

from app.modules.backup.backup import Backup
from app.modules.cnc.cnc import CncServer

from app.modules.backup.backup_dto import BackupDto
from app.modules.auth.auth_controller import AuthController
from app.modules.policy.rules_file.rules_file import RulesFile
from app.modules.policy.rule.rule import Rule
from utils.file_handler import remove_file
from utils.policy.policy_handler import get_rules_for_restore, get_blacklist_from_file
from utils.message_code import ErrorCode
from utils.util import backup_file, datetime_2_int, differ_from_blacklist, get_cnc_status, restore_rule_file, get_rule_file_path, save_rules_2_file
from utils.response import send_error, send_result


class BackupController():

    def get(self, args):
        '''
        Get all backup information in the system
        
        :return: list of backup information
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            backups = {}
            if args.type:
                backups = Backup.query.filter_by(
                    backup_type=args.type
                ).order_by(Backup.created_at.desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)
            else:
                backups = Backup.query.order_by(Backup.created_at.desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)
            
            items = marshal(backups.items, BackupDto.model_response)
            res = {
                "page": backups.page,
                "number_in_page": len(items),
                
                "pages": backups.pages,
                "total": backups.total,
                "items": items
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            print(e.__str__())
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message="Could not load error, please try again later.")
    
    def get_by_id(self, object_id):
        '''
        Get backup by ID

        :param object_id: The backup id

        :return: The backup if found and None vice versa.
        '''
        if object_id is None:
            return send_error(message="The backup ID must not be null.")
        try:
            backup = Backup.query.filter_by(id=object_id).first()
            if backup is None:
                return send_error(data="Could not find backup by this id")
            else:
                return send_result(data=marshal(backup, BackupDto.model_response))
        except Exception as e:
            print(e.__str__())
            return send_error(message='Could not get backup by ID {}.'.format(object_id))
        
    def create(self, data, req):
        '''
        Create new backup

        :param data: this is data to create new backup (in dictionary format)

        :return: Return backup if created successfully and vice versa.
        '''
        if not isinstance(data, dict):
            return send_error(message="Data is not correct or not in dictionary type")
        if not 'backup_type' in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request doesn\'t have backup type') 
        try:
            if data['backup_type'] not in ['blacklist', 'whitelist', 'rules']:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Back up type must be in [blacklist, whitelist or rules]')
            if data['backup_type'] != 'rules' and 'file_id' in data:
                return send_error(code=ErrorCode.BAD_REQUEST, message='File ID is only use when backup type is rules')
            
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(code=ErrorCode.NOT_FOUND, message=message)
            
            bk = Backup()
            bk.created_by = user.email
            bk.backup_type = data['backup_type']
            
            tmp_time = datetime.now()
            source_file = ""
            target_file = ""
            
            if data['backup_type'] == 'rules':
                
                rule_file = RulesFile.query.filter_by(id=data['file_id']).first()
                if rule_file is None:
                    return send_error(code=ErrorCode.NOT_FOUND, message='file not exists')
                
                bk.file_id = rule_file.id
                bk.num_of_rules = rule_file.last_index
                
                source_file = get_rule_file_path(rule_file.file_type) + rule_file.file_name
                target_file = '/etc/snort/backup/' + rule_file.file_name + '.' + str(datetime_2_int(tmp_time))
            
            if data['backup_type'] == 'blacklist':
                source_file = '/etc/snort/rules/black_list.rules'
                target_file = '/etc/snort/backup/black_list.' + str(datetime_2_int(tmp_time)) + '.rules'
                
            if data['backup_type'] == 'whitelist':
                source_file = '/etc/snort/rules/white_list.rules'
                target_file = '/etc/snort/backup/white_list.' + str(datetime_2_int(tmp_time)) + '.rules'

            ok, err = backup_file(source_file, target_file)
            if ok == True:
                bk.path = target_file
                bk.created_at = str(tmp_time)
                
                bks = Backup.query.filter_by(backup_type=data['backup_type']).count()
                if bks >= 10:
                    min_time_bks = Backup.query.filter_by(backup_type=data['backup_type'])
                    if data['backup_type'] == 'rules':
                        min_time_bks = min_time_bks.filter_by(file_id=data['file_id'])
                    
                    min_time_bks = min_time_bks.order_by(Backup.created_at).limit(bks - 10).all()
                    for min_time_bk in min_time_bks:
                        remove_file(min_time_bk.path)
                        db.session.delete(min_time_bk)
                
                db.session.add(bk)
                db.session.commit()
                return send_result(code=200, data=marshal(bk, BackupDto.model_response))
            
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def restore_by_id(self, object_id, req):
        '''
        Restore rule file
        
        :param object_id: backup ID
        
        :return: True if restore successfully and vice versa
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message='id can not be None')
        try:
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
            
            backup = Backup.query.filter_by(id=object_id).first()
            if backup is None:
                return send_error(code=ErrorCode.NOT_FOUND, message='backup not found')

            if backup.backup_type == 'rules':
                rule_file = RulesFile.query.filter_by(id=backup.file_id).first()
                if rule_file is None:
                    return send_error(code=ErrorCode.NOT_FOUND, message='rule_file not found')
                
                target_file = get_rule_file_path(rule_file.file_type) + rule_file.file_name
                
                rules, message = get_rules_for_restore(backup.path)
                if rules is None: 
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=message)
                
                # write to file
                ok, err = save_rules_2_file([rule['rule'] + '\n' for rule in rules], target_file, True)
                if not ok:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
                # write to db
                tmp_time = datetime.now()
                rule_file.last_index = len(rules) - 1
                rule_file.updated_by = user.email
                rule_file.updated_at = str(tmp_time)
                for rule in rules:
                    tmp = Rule()
                    tmp.file_id = rule_file.id
                    
                    tmp.raw_text = rule['rule']
                    tmp.rule_index = rule['rule_index']
                    tmp.rule_status = rule['status']
                    
                    tmp.created_at = str(tmp_time)
                    tmp.created_by = user.email
                    tmp.updated_at = str(tmp_time)
                    
                    tmp.updated_by = user.email
                    db.session.add(tmp)
                remove_file(backup.path)
                # romve backup file info in db
                db.session.delete(backup)
                db.session.commit()
                return send_result(code=200, message='Success')
            else:
                blacklist, message = get_blacklist_from_file(backup.path)
                if blacklist is None:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=message)
                tmp_time = datetime.now()
                
                
                target_f = '/etc/snort/rules/black_list.rules' if backup.backup_type == 'blacklist' \
                                                            else '/etc/snort/rules/white_list.rules'
                ok, err = save_rules_2_file([cnc['row'] for cnc in blacklist], target_f, True)
                remove_file(backup.path)
                rule_file = CncServer.query.delete()
                for bl in blacklist:
                  cnc = CncServer()
                  cnc.address = bl['address']
                  cnc.status = bl['status']
                  cnc.type = 'ipv4'
                  cnc.created_by = user.email
                  cnc.created_at = str(tmp_time)
                  cnc.updated_by = user.email
                  
                  cnc.updated_at = str(tmp_time)
                  db.session.add(cnc)
                db.session.delete(backup)
                db.session.commit()
                
                return send_result(code=200, message='Success')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__()) 

    def delete(self, object_id):
        '''
        Delete backup with backup ID
        ----------------------------
        
        :return: True if successfully and vice versa
        '''
        if not object_id:
            return send_error(code=ErrorCode, message='Backup ID must not be null')
        try:
            bk = Backup.query.filter_by(id=object_id).first()
            if not bk:
                return send_error(code=ErrorCode.NOT_FOUND, message="Backup not found")
            
            remove_file(bk.path)
            db.session.delete(bk)
            db.session.commit()
            return send_result(code=200, message="Success")
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    @staticmethod
    def backup(data):
        '''
        For automatic backup
        '''
        if 'backup_type' not in data:
            return False, "Data must have backup type"
        if 'created_by' not in data:
            return False, "Data must specify the one that do this action"
        if 'created_at' not in data:
            return False, "Data must have the time that do this action"
        if data['backup_type'] == 'rules' and (
            'file_id' not in data 
            or 'num_of_rules' not in data
        ):
            return False, "Backup rule must be specify rule file to backup"
        
        bk = Backup()
        bk.backup_type = data['backup_type']
        bk.created_by = data['created_by']
        bk.created_at = str(data['created_at'])
        
        if data['backup_type'] == "rules":
            rule = RulesFile.query.filter_by(id=data['file_id']).first()
            if not rule:
                return False, "Rule File doesn't exist"
            
            bk.path = "/etc/snort/backup/" + rule.file_name + '.' + str(datetime_2_int(bk.created_at))
            bk.file_id = rule.id
            
            source_file = get_rule_file_path(rule.file_type) + rule.file_name
            ok, err = backup_file(source_file, bk.path)
            if not ok:
                return False, err
            
        else:
            source_file = "/etc/snort/rules/black_list.rules" \
                            if data["backup_type"] == "blacklist" \
                            else "/etc/snort/rules/white_list.rules"
            
            bk.path = data['path'] 
            ok, err = backup_file(source_file, data['path'])
            if not ok:
                return False, err
        
        db.session.add(bk)
        db.session.commit()
        
        return True, None
    