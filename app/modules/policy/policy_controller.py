from http.client import INTERNAL_SERVER_ERROR
import os
from flask_restx import marshal
from sqlalchemy import func
from datetime import datetime

from app import db
from app.modules.auth.auth_controller import AuthController
from app.modules.policy.policy_dto import PolicyDto

from app.modules.policy.rule.rule import Rule
from app.modules.policy.rules_file.rules_file import RulesFile
from app.modules.backup.backup import Backup
from app.modules.setup.setting import Setting
from utils.file_handler import remove_file

from utils.message_code import ErrorCode
from utils.response import send_error, send_result
from utils.policy.policy_handler import *
from utils.util import add_2_conf, add_msg_2_sidmap, add_rule_to_file, backup_file, check_file_name, datetime_2_int, delete_rule_from_file, get_rule_file_path, list_2_dict, match_rule_in_file, save_rules_2_file, update_rule_from_file, update_status_rules_file

class PolicyController():

    def get(self):
        pass

    def create(self, data):
        '''
        Create a new Policy

        :param data: The information of Policy

        :return: Return policy if create successfully and vise versa.
        '''
        try:
            keys = data.keys()
            ok, err = self.check_header(data)
            if ok is False:
                return send_error(code=ErrorCode.BAD_REQUEST, message=err)
            
            ok, err = self.check_general(data)
            if ok is False:
                return send_error(code=ErrorCode.BAD_REQUEST, message=err)
            
            if 'detection' in keys:
                ok, err = self.check_detection(data["detection"])
                if ok is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message=err)

            if 'non_detection' in keys:
                ok, err = self.check_non_detection(data["non_detection"])
                if ok is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message=err)
                
            if 'post_detection' in keys:
                ok, err = self.check_post_detection(data["post_detection"])
                if ok is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message=err)
                
            policy_str = policy_2_str(data)
            return send_result(code=200, data=policy_str)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    def check_header(self, data):
        header = data['header']
        keys = header.keys()
        if 'action' in keys:
            if check_action(header['action']) is False:
                return False, 'action value must be in (alert, log, pass, activate, dynamic)'
        else:
            return False, 'action must be in header'

        if 'protocol' in keys:
            if check_protocol(header['protocol']) is False:
                return False, 'protocol value must be in (tcp, udp, icmp, ip)'
        else:
            return False, 'protocol must be in header'

        if 'source_ip' in keys:
            if check_ip(header['source_ip'], AddrTypes.SRC) is False:
                return False, 'source address is not in the correct format'
        else:
            return False, 'source address value must be in header'
        
        if 'source_port' in keys:
            if check_port(header['source_port'], AddrTypes.SRC) is False:
                return False, 'source port is not in the correct format'
        else:
            return False, 'source port must be in header'
        
        if 'direction' in keys:
            if check_direction(header['direction']) is False:
                return False, 'direction is not in the correct format'
        else:
            return False, 'direction must be in header'
        
        if 'dest_ip' in keys:
            if check_ip(header['dest_ip'], AddrTypes.DST) is False:
                return False, 'destination address is not in the correct format'
        else:
            return False, 'destination address must be in header'
        
        if 'dest_port' in keys:
            if check_port(header['dest_port'], AddrTypes.DST) is False:
                return False, 'destination port is not in the correct format'
        else:
            return False, 'destination port must be in header'

        return True, None

    def check_general(self, data):
        general = data['general']
        keys = general.keys()
        if 'msg' not in keys:
            return False, 'msg must be in general'
        
        if 'gid' not in keys:
            return False, 'gid must be in general'
        
        if 'sid' not in keys:
            return False, 'sid must be in general'
        
        if 'rev' not in keys:
            return False, 'rev must be in general'
        
        if 'priority' not in keys:
            return False, 'priority must be in general'
        else:
            if check_priority(general['priority']) is False:
                return False, 'priority must be between ' + str(priority['minimum']) + ' and ' + str(priority['maximum'])

        if 'classtype' not in keys:
            return False, 'classtype must be in general'
        else:
            if check_classtype(general['classtype']) is False:
                return False, 'classtype must be in ' + str(classtypes)

        if 'metadata' in keys:
            if check_metadata(general['metadata']) is False:
                return False, 'metadata is not in the correct format'
        if 'reference' in keys:
            if check_reference(general['reference']) is False:
                return False, 'reference is not in the correct format'
        
        return True, None
    
    def check_detection(self, data):
        keys = data.keys()
        print(keys)
        if 'content' in keys:
            if check_contents(data['content']) is False:
                return False, 'Contents data is incorrect format'
        if 'protected_content' in keys:
            if check_protected_contents(data['protected_content']) is False:
                return False, 'Protected_Contents data is incorrect format'
        # if 'http_encode' in keys:
        #     pass
        # if 'uricontent' in keys:
        #     pass
        if 'urilen' in keys:
            if check_urilen(data['urilen']) is False:
                return False, 'urilen is incorrect format'
        # if 'prce' in keys:
        #     pass
        if 'pkt_data' in keys:
            if check_pkt_data(data['pkt_data']) is False:
                return False, 'pkt_data is incorrect format'
        if 'file_data' in keys:
            if check_file_data(data['file_data']) is False:
                return False, 'file_data is incorrect format'
        if 'base64' in keys:
            if check_base64(data['base64']) is False:
                return False, 'base64 is incorrect format'
        # if 'byte_test' in keys:
        #     pass
        # byte_jump
        # byte_extract
        # byte_math
        # ftpbounce
        # asn1
        # cvs
        # others
        return True, None

    def check_non_detection(self, data):
        keys = data.keys()
        if 'fragoffset' in keys:
            if check_fragoffset(data['fragoffset']) is False:
                return False, 'fragoffset is incorrect format'
        
        if 'ttl' in keys:
            if check_ttl(data['ttl']) is False:
                return False, 'ttl is incorrect format'
        
        if 'tos' in keys:
            if check_tos(data['tos']) is False:
                return False, 'tos is incorrect format'

        if 'ipopts' in keys:
            if check_ipopts(data['ipopts']) is False:
                return False, 'ipopts is incorrect format'
        
        # fragbits 
        # dsize
        if 'flags' in keys:
            if check_flags(data['flags']) is False:
                return False, 'flags is incorrect format'
        
        if 'flow' in keys:
            if check_flow(data['flow']) is False:
                return False, 'flow is incorrect format'
        
        # if 'flowbits' in keys:
        #     if check_flowbits(data['flowbits']) is False:
        #         return False, 'flowbits is incorrect format'
        if 'window' in keys:
            if check_window(data['window']) is False:
                return False, 'window is incorrect format'
        
        # itype
        # icode
        # rpc
        if 'ip_proto' in keys:
            if check_ip_proto(data['ip_proto']) is False:
                return False, 'ip_proto is incorrect format'

        if 'stream_reassemble' in keys:
            if check_stream_reassemble(data['stream_reassemble']) is False:
                return False, 'stream_reassemble is incorrect format'
        
        if 'stream_size' in keys:
            if check_stream_size(data['stream_size']) is False:
                return False, 'stream_size is incorrect format'
        
        return True

    def check_post_detection(self, data):
        keys = data.keys()
        if 'logto' in keys:
            if check_logto(data['logto']) is False:
                return False, 'logto value is incorrect format'

        if 'session' in keys:
            if check_session(data['session']) is False:
                return False, 'session value is incorrect format'

        if 'tag' in keys:
            pass

        if 'detection_filter' in keys:
            if check_detection_filter(data['detection_filter']) is False:
                return False, 'detection_filter is incorrect format'

        return True

    def get_file(self, args):
        '''
        Get all rule files in the system
        
        :return: list rule files infomation
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = RulesFile.query.order_by(RulesFile.file_name).paginate(
                page=page, per_page=pageSize, error_out=False
            )
            
            items = marshal(data.items, PolicyDto.model_file_response)
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def get_file_by_id(self, object_id):
        '''
        Get rule file by file ID
        
        :param object_id: file ID
        
        :return: rule file information
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="File ID must not be null")
        try:
            file = RulesFile.query.filter_by(id=object_id).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message="File not found")
            return send_result(code=200, data=marshal(file, PolicyDto.model_file_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    def get_file_by_name(self, object_name):
        '''
        Get rule file by file ID
        
        :param object_id: file ID
        
        :return: rule file information
        '''
        if object_name is None:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="File ID must not be null")
        try:
            file = RulesFile.query.filter_by(file_name=object_name).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message="File not found")
            return send_result(code=200, data=marshal(file, PolicyDto.model_file_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def create_file(self, args, req):
        '''
        Add a rule file into the system
        
        :param data: dictionary
        
        :param req: request
        
        :return: rule file infor if successfully and vice versa
        '''
        if not isinstance(args, dict) or not 'file' in args:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not contain file.')
        if not 'file_name' in args:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not contain file name')
        
        if not 'file_type' in args:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not contain file type')
        if not 'file_status' in args:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not contain file status')
        try:
            overwrite = True if args.overwrite else False
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
            
            if check_file_name(args['file_name']) is False:
                return send_error(code=ErrorCode.BAD_REQUEST, message='File name is invalid')
            
            _file = RulesFile.query.filter_by(file_type=args['file_type'])\
                                    .filter_by(file_name=args['file_name']).first()
            if _file and not overwrite:
                return send_error(code=ErrorCode.RULE_FILE_ALREADY_EXIST, message='File name already exist')
            if not _file and overwrite == True:
                return send_error(code=ErrorCode.RULE_FILE_ALREADY_EXIST, message='File not found')
            
            
            path = get_rule_file_path(args['file_type'])
            rfile = args['file']
            rules, messages = check_uploaded_rule_file(rfile)
            
            if not rules:
                return send_error(code=ErrorCode.BAD_REQUEST, message=" ".join(x for x in messages))
            ok, err = save_rules_2_file([rule['rule'] + '\n' for rule in rules], path + args['file_name'], overwrite)
            if not ok:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            if not overwrite:    
                file = RulesFile()
                file.file_name = args['file_name']
                file.file_status = args['file_status']
                file.file_type = args['file_type']
                
                file.last_index = len(rules) - 1
                file.created_by = user.email
                file.updated_by = user.email
                
                tmp_time = datetime.now()
                file.created_at = str(tmp_time)
                file.updated_at = str(tmp_time)
            
                ok, err = add_2_conf(file.file_name, file.file_type, file.file_status)
                if not ok:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
                
                db.session.add(file)
            else:
                _file.last_index = len(rules) - 1
                
            if _file and overwrite:
                rules = Rule.query.filter_by(file_id=_file.id).all()
                for rule in rules:
                    db.session.delete(rule)
                db.session.commit()
            db.session.commit()
            
            f = RulesFile.query.filter_by(file_name=file.file_name)\
                                .filter_by(file_type=file.file_type).first()
            if not f:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message="Can't save info to db")
            
            for rule in rules:
                tmp = Rule()
                tmp.file_id = f.id
                
                tmp.raw_text = rule['rule']
                tmp.rule_index = rule['rule_index']
                tmp.rule_status = rule['status']
                
                tmp.created_at = str(tmp_time)
                tmp.created_by = user.email
                tmp.updated_at = str(tmp_time)
                
                tmp.updated_by = user.email
                db.session.add(tmp)
            db.session.commit()
            
            return send_result(code=200, data=marshal(file, PolicyDto.model_file_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def update_file(self, object_id, data, req):
        '''
        Update rule file
        
        :param object_id: file ID
        
        :param data: data dictionary to update
        
        :param req: request
        
        :return:
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message='File ID must not be null')
        if not isinstance(data, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data must be instance of dictionary')
        if 'file_type' in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Can\'t update rule file type')
        
        try:
            file = RulesFile.query.filter_by(id=object_id).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule File not found')
            
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
                
            if 'file_status' in data:
                file.file_status = data['file_status']
            
            tmp_time = datetime.now()
            file.updated_by = user.email
            file.updated_at = str(tmp_time)
            
            ok, err = update_status_rules_file(file.file_name, file.file_type, file.file_status)
            if not ok:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            db.session.commit()
            return send_result(code=200, data=marshal(file, PolicyDto.model_file_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
             
    def delete_file(self, object_id):
        '''
        Delete rule file
        
        :return: True if successfully and vice versa
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message='File ID must not be null')
        try:
            file = RulesFile.query.filter_by(id=object_id).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message='File not found')
            
            filepath = get_rule_file_path(file.file_type) + file.file_name
            remove_file(filepath)
            
            backups = Backup.query.filter_by(file_id=object_id).all()
            for backup in backups:
                remove_file(backup.path)
                db.session.delete(backup)
            
            rules = Rule.query.filter_by(file_id=object_id).all()
            for rule in rules:
                db.session.delete(rule)
            db.session.delete(file)
            db.session.commit()
            
            return send_result(code=200, message='Success')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
      
    def get_total_file(self):
        '''
        Get number of rule files in the system
        
        :return: number of rule files
        '''
        try:
            total = RulesFile.query.count()
            return send_result(code=200, data=total)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def get_total_rule(self):
        '''
        Get number of rule in the system
        
        :return: number of rule
        '''
        try:
            total = Rule.query.count()
            return send_result(code=200, data=total)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def get_recent_update(self):
        '''
        Get recent update time of rule
        '''
        try:
            recent_time = db.session.query(func.max(Rule.updated_at)).first()
            return send_result(code=200, data=str(recent_time[0]))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
      
    def get_rule(self, args):
        '''
        Get all rules from rule file by file ID
        
        :param file_id: file ID
        
        :return: list rules
        '''
        if not isinstance(args, dict) or 'file_id' not in args:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Your request does not have file id")
        try:
            page = args['page'] if 'page' in args else 1
            pageSize = args['pageSize'] if 'pageSize' in args else 15
            
            rules = Rule.query.filter_by(
                file_id=args['file_id']
            ).paginate(page=page, per_page=pageSize, error_out=False).items
            
            return send_result(code=200, data=marshal(rules, PolicyDto.model_rule_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def create_rule(self, data, req):
        '''
        Create rule
        
        :param data: dictionary
        
        :param req: request
        
        :return:
        '''
        if not isinstance(data, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data must be an instance of dictionary')
        
        if 'rule_status' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have rule status')
        if 'raw_text' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have raw text')
        if 'file_id' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have rule file ID')
        try:
            data['raw_text'] = data['raw_text'].strip()
            if data['raw_text'][0] == '#':
                return send_error(code=ErrorCode.BAD_REQUEST, message="'#' at the begining of raw_text meaning rule is disable. Please remove '#' character and change rule_status is false.")
            
            pobj, err = parse_policy_obj(data['raw_text'])
            if not pobj:
                return send_error(code=ErrorCode.BAD_REQUEST, message=err)
            
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
            
            file = RulesFile.query.filter_by(id=data['file_id']).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule File not found')
            
            rules = db.session.query(Rule).filter(Rule.file_id==data['file_id']).with_entities(Rule.raw_text).all()
            if not match_rule_in_file(data['raw_text'], rules):
                return send_error(code=ErrorCode.BAD_REQUEST, message='Raw text already exist')
            
            rule = Rule()
            rule.raw_text = data['raw_text']
            rule.rule_status = data['rule_status']
            rule.file_id = file.id
            
            rule.rule_index = file.last_index
            rule.created_by = user.email
            rule.updated_by = user.email
            
            tmp_time = datetime.now()
            rule.created_at = tmp_time
            rule.updated_at = tmp_time
            
            file.last_index += 1
            file.updated_by = user.email
            file.updated_at = tmp_time
            filepath = get_rule_file_path(file.file_type) + file.file_name
            
            st_bk = Setting.query.filter_by(setting_type='backup').first()
            if not st_bk:
                print("Can't backup due to setting backup doesn't exist")
            else:
                if st_bk.state == 1 or st_bk.state == 3:
                    path = '/etc/snort/backup/{0}.'.format(file.file_name) + str(datetime_2_int(tmp_time))
                    ok, err = self.backup({
                        "created_by": user.email,
                        "created_at": tmp_time,
                        
                        "backup_type": "rules",
                        "path": path,
                        
                        "source_file": filepath,
                        "file_id": file.id,
                        "num_of_rules": file.last_index
                    })
                    if not ok:
                        print(err)
            
            ok, err = add_rule_to_file(rule.raw_text, rule.rule_status, filepath)
            if not ok:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            ok, err = add_msg_2_sidmap(pobj['general'])
            if not ok:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            db.session.add(rule)
            db.session.commit()
            return send_result(code=200, data=marshal(rule, PolicyDto.model_rule_response))
        
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
            
    def get_rule_by_id(self, object_id):
        '''
        Get rule by rule ID
        
        :param object_id: rule ID
        
        :return:
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message='Rule ID must not be null')
        try:
            rule = Rule.query.filter_by(id=object_id).first()
            if not rule:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule not found')
            
            return send_result(code=200, data=marshal(rule, PolicyDto.model_rule_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
          
    
    def update_rule(self, object_id, data, req):
        '''
        Update rule
        
        :param object_id: rule ID
        
        :param data: dictionary
        
        :param req: request
        
        :return:
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Rule ID must not be null')
        if not isinstance(data, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data must be an instance of dictionary')
        
        if 'file_id' in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='File ID can\'t modify')
        try:
            
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
            
            rule = Rule.query.filter_by(id=object_id).first()
            if not rule:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule not found')
            
            if 'raw_text' in data:
                data['raw_text'] = data['raw_text'].strip()
                if data['raw_text'][0] == '#':
                    return send_error(code=ErrorCode.BAD_REQUEST, message="'#' at the begining of raw_text meaning rule is disable. Please remove '#' character and change rule_status is false.")
            
                pobj, err = parse_policy_obj(data['raw_text'])
                if not pobj:
                    return send_error(code=ErrorCode.BAD_REQUEST, message=err)
                
                tmp = Rule.query.filter(Rule.file_id==rule.file_id, Rule.raw_text==data['raw_text']).first()
                if tmp:
                    return send_error(code=ErrorCode.BAD_REQUEST, message='Raw text already exist')
            
            rule.updated_by = user.email
            tmp_time = datetime.now()
            rule.updated_at = str(tmp_time)
            
            file = RulesFile.query.filter_by(id=rule.file_id).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule File isn\'t exist')
            
            if 'rule_status' in data:
                rule.rule_status = data['rule_status']
            
            ntext = ""
            if 'raw_text' in data:
                ntext = "# " + data['raw_text'] if not rule.rule_status else data['raw_text']
                
            else:
                if rule.rule_status:
                    ntext = rule.raw_text.strip('#').strip()
                    
                else:
                    ntext = "# " + rule.raw_text.strip('#').strip()
            otext = rule.raw_text
            
            filepath = get_rule_file_path(file.file_type) + file.file_name
            st_bk = Setting.query.filter_by(setting_type='backup').first()
            if not st_bk:
                print("Can't backup due to setting backup doesn't exist")
                
            else:
                if st_bk.state == 1 or st_bk.state == 3:
                    path = '/etc/snort/backup/{0}.'.format(file.file_name) + str(datetime_2_int(tmp_time))
                    ok, err = self.backup({
                        "created_by": user.email,
                        "created_at": tmp_time,
                        
                        "backup_type": "rules",
                        "path": path,
                        
                        "source_file": filepath,
                        "file_id": file.id,
                        "num_of_rules": file.last_index
                    })
                    if not ok:
                        print(err)
            
            ok, err = update_rule_from_file(
                file.file_name, file.file_type,
                rule.rule_index, rule.rule_status,
                otext, ntext
            )
            
            if not ok:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            rule.raw_text = ntext
            db.session.commit()
            
            return send_result(code=200, data=marshal(rule, PolicyDto.model_rule_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def delete_rule(self, object_id, req):
        '''
        Delete rule
        
        :param: rule ID
        
        :return: 
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Rule ID must not be null')
        try:
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
            
            rule = Rule.query.filter_by(id=object_id).first()
            if not rule:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule not found')
            
            file = RulesFile.query.filter_by(id=rule.file_id).first()
            if not file:
                return send_error(code=ErrorCode.NOT_FOUND, message='Rule File isn\'t exist')
            
            filepath = get_rule_file_path(file.file_type) + file.file_name
            tmp_time = datetime.now()
            st_bk = Setting.query.filter_by(setting_type='backup').first()
            if not st_bk:
                print("Can't backup due to setting backup doesn't exist")
                
            else:
                if st_bk.state == 1 or st_bk.state == 3:
                    path = '/etc/snort/backup/{0}.'.format(file.file_name) + str(datetime_2_int(tmp_time))
                    ok, err = self.backup({
                        "created_by": user.email,
                        "created_at": tmp_time,
                        
                        "backup_type": "rules",
                        "path": path,
                        
                        "source_file": filepath,
                        "file_id": file.id,
                        "num_of_rules": file.last_index
                    })
                    if not ok:
                        print(err)
                        
            ok, err = delete_rule_from_file(
                file.file_name, 
                file.file_type,
                
                rule.raw_text,
                rule.rule_index,
                rule.rule_status
            )
            
            if not ok:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            db.session.delete(rule)
            db.session.commit()
            
            return send_result(code=200, message='Deleted')
        except Exception as e:
            print(e.__str__())
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
            
    
    def parse_policy(self, policy):
        '''
        Convert policy line string to policy dictionary object

        :param policy: string

        :return: Return policy object if parse success and error message vice versa.
        '''
        try:
            policy = policy.strip()
            policy_obj, err = parse_policy_obj(policy)
            if err is None:
                return send_result(code=200, data=policy_obj)
            else:
                return send_error(code=ErrorCode.BAD_REQUEST, message=err)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def backup(self, data):
        '''
        For automatic backup
        '''
        if 'backup_type' not in data:
            return False, "Data must have backup type"
        if 'created_by' not in data:
            return False, "Data must specify the one that do this action"
        if 'created_at' not in data:
            return False, "Data must have the time that do this action"

        bk = Backup()
        bk.backup_type = data['backup_type']
        bk.path = data['path']
        bk.num_of_rules = data['num_of_rules']
        
        bk.created_by = data['created_by']
        bk.created_at = str(data['created_at'])
        bk.file_id = data['file_id']
        
        source_file = data['source_file']
        ok, err = backup_file(source_file, data['path'])
        if not ok:
            return False, err
        
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
        return True, None
    