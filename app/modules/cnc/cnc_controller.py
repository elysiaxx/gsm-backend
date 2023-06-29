from flask_restx import marshal
from datetime import datetime
from app import db
from app.modules.backup.backup import Backup

from app.modules.cnc.cnc_dto import CncDto
from app.modules.cnc.cnc import CncServer

from app.modules.auth.auth_controller import AuthController
from app.modules.policy.rules_file.rules_file import RulesFile
from app.modules.setup.setting import Setting
from utils.file_handler import remove_file

from utils.response import send_error, send_result
from utils.message_code import ErrorCode
from utils.util import backup_file, check_address, check_domain, cnc_2_file, datetime_2_int, delete_cnc_2_file, get_lines_from_fileStorage, get_rule_file_path, update_cnc_2_file
from utils.util import get_addrs

class CncController():
    
    def get(self, args):
        '''
        Get all cnc server infor in the system
        
        :return: list cnc servers
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = CncServer.query.order_by(
                CncServer.created_at.desc()
            )
            
            if args.type:
                data = data.filter_by(type=args.type)
            data = data.paginate(page=page, per_page=pageSize, error_out=False)
            
            res = {
                "page": data.page,
                "number_in_page": len(data.items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(data.items, CncDto.model_response)
            }
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def create(self, data, req):
        '''
        Create cnc server and add into the system
        
        :param data: cnc server dictionary
        
        :param req: create request
        
        :return: cnc server info
        '''
        if isinstance(data, dict) is False:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data is not correct or not in dictionary type')
        if 'address' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Address must be in data dictionary')
        
        if 'type' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have cnc address type')
        if 'status' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have cnc status')
        
        try:
            if data['type'] not in ['ipv4', 'domain_name']:
                return send_error(code=ErrorCode.BAD_REQUEST, message='cnc type must be in ["ipv4", "domain_name"]')
            
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(code=ErrorCode.NOT_FOUND, message=message)
            
            tmp_time = datetime.now()
            if data['type'] == 'ipv4':
                ok, err = check_address(data['address'])
                if ok is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message=err)
                
                st_bk = Setting.query.filter_by(setting_type='backup').first()
                if not st_bk:
                    print("Can't backup {0} due to setting backup doesn't exist".format('black_list.rules'))
                else:
                    if st_bk.state == 2 or st_bk.state == 3:
                        path = '/etc/snort/backup/black_list.rules.' + str(datetime_2_int(tmp_time))
                        ok, err = self.backup({
                            "created_by": user.email,
                            "created_at": tmp_time,
                            
                            "backup_type": "blacklist",
                            "path": path
                        })
                        if not ok:
                            print(err)
                
                ok, err = cnc_2_file(data['address'], '/etc/snort/rules/black_list.rules', data['status'])
                if ok is False:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            elif data['type'] == 'domain_name':
                if not check_domain(data['address']):
                    return send_error(code=ErrorCode.BAD_REQUEST, message="Invalid Cnc address")
            else:
                pass
            
            cncS = self._parse_cnc(data=data, cncS=None)
            cncS.created_by = user.email
            cncS.updated_by = user.email 
            
            cncS.created_at = str(tmp_time)
            cncS.updated_at = str(tmp_time)
            
            db.session.add(cncS)
            db.session.commit()
            return send_result(code=200, data=marshal(cncS, CncDto.model_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
            
    def update(self, object_id, data, req):
        '''
        Update cnc server info
        
        :param object_id: Cnc Server ID
        
        :param data:
        
        :param req: update request
        
        :return: 
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Cnc ID must not be null")
        if isinstance(data, dict) is False:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Data is not correct or not in dictionary type")
        if 'address' in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Can't change address of cnc")
        if 'type' in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Can't change type of cnc")
        try:
            cncS = CncServer.query.filter_by(id=object_id).first()
            if cncS is None:
                return send_error(code=ErrorCode.NOT_FOUND, message="Cnc Server not found")
            
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(code=ErrorCode.NOT_FOUND, message=message)
            
            if 'status' in data:
                if cncS.status != data['status']:
                    ok, err = update_cnc_2_file(cncS.address, data['status'], '/etc/snort/rules/black_list.rules')
                    if ok is False:
                        return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            cncS = self._parse_cnc(data=data, cncS=cncS)
            cncS.updated_by = user.email
            cncS.updated_at = str(datetime.now())
            
            db.session.commit()
            return send_result(code=200, data=marshal(cncS, CncDto.model_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def delete(self, object_id):
        '''
        Delete cnc server
        
        :return: True if successfully and vice versa
        '''
        if object_id is False:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="Cnc server ID must not be null")
        try:
            cncS = CncServer.query.filter_by(id=object_id).first()
            if cncS is None:
                return send_error(code=ErrorCode.NOT_FOUND, message="Cnc server not found")
            
            ok, err = delete_cnc_2_file(cncS.address, '/etc/snort/rules/black_list.rules')
            if ok is False:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            db.session.delete(cncS)
            db.session.commit()
            return send_result(code=200)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    def get_by_id(self, object_id):
        '''
        Get cnc server by ID
        
        :return: cnc server info
        '''
        if object_id is False:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="Cnc server ID must not be null")
        try:
            cncS = CncServer.query.filter_by(id=object_id).first()
            if cncS is None:
                return send_error(code=ErrorCode.NOT_FOUND, message="Cnc server not found")
            
            return send_result(code=200, data=marshal(cncS, CncDto.model_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def upload(self, args, req):
        '''
        Upload cnc file
        ---------------------
        
        :param:
        
        :return: 
        '''
        if not isinstance(args, dict) or not 'file' in args:
            return send_error(message='Your request does not contain cnc file.')
        if 'overwrite' not in args:
            return send_error(message='Your request does not contain overwrite query param')
        
        user, message = AuthController.get_logged_user(req=req)
        if not user:
            return send_error(code=ErrorCode.NO_SUCH_USER, message=message)

        try:
            print(args['overwrite'])
            cnc_file = args['file']
            lines = get_lines_from_fileStorage(cnc_file)
            print(lines)
            if not lines:
                return send_error(code=ErrorCode.BAD_REQUEST, message="Can't read file")
            
            tmp_time = datetime.now()
            addrs, err = get_addrs(lines)
            if err:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)

            print(addrs)
            st_bk = Setting.query.filter_by(setting_type='backup').first()
            
            if not st_bk:
                print("Can't backup {0} due to setting backup doesn't exist".format('black_list.rules'))
            else:
                if st_bk.state == 2 or st_bk.state == 3:
                    path = '/etc/snort/backup/black_list.rules.' + str(datetime_2_int(tmp_time))
                    ok, err = self.backup({
                        "created_by": user.email,
                        "created_at": tmp_time,
                        
                        "backup_type": "blacklist",
                        "path": path
                    })
                    if not ok:
                        print(err)
                        
            res = []
            message = ""
            if not args['overwrite']:
                for addr in addrs:
                    cnc = CncServer.query.filter_by(address=addr['address']).first()
                    if cnc:
                        message += "Cnc {0} already exist".format(addr['address'])
                        continue
                    
                    ok, err = cnc_2_file(addr["address"], "/etc/snort/rules/black_list.rules", addr["status"])
                    if not ok:
                        print(err)
                        continue
                    cncS = self._parse_cnc(addr, None)
                    print(cncS)
                    cncS.created_by = user.email
                    cncS.created_at = str(tmp_time)
                    cncS.updated_by = user.email
                    cncS.updated_at = str(tmp_time)
                    
                    res.append(cncS)
                    db.session.add(cncS)
                    
                db.session.commit()
                return send_result(code=200, data=marshal(res, CncDto.model_response), message=message)
            else:
                cncS = CncServer.query.all()
                for cnc in cncS:
                    db.session.delete(cnc)
                db.session.commit()
                for addr in addrs:
                    print(addr)
                    ok, err = cnc_2_file(addr["address"], "/etc/snort/rules/black_list.rules", addr["status"])
                    if not ok:
                        print(err)
                        continue
                    cnc = self._parse_cnc(addr, None)
                    cnc.type = 'ipv4'
                    cnc.created_by = user.email
                    cnc.created_at = str(tmp_time)
                    cnc.updated_by = user.email
                    cnc.updated_at = str(tmp_time)
                    
                    res.append(cnc)
                    db.session.add(cnc)
                    db.session.commit()
                
                return send_result(code=200, data=marshal(res, CncDto.model_response), message=message)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    def _parse_cnc(self, data, cncS=None):
        if cncS is None:
            cncS = CncServer()
            
        if 'address' in data:
            cncS.address = data['address']
        if 'description' in data:
            cncS.description = data['description']
            
        if 'type' in data:
            cncS.type = data['type']
        if 'status' in data:
            cncS.status = data['status']
            
        return cncS
    
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
        
        bk.created_by = data['created_by']
        bk.created_at = str(data['created_at'])
        
        source_file = "/etc/snort/rules/black_list.rules"
        ok, err = backup_file(source_file, data['path'])
        if not ok:
            return False, err
        
        cnc_bks = Backup.query.filter_by(backup_type='blacklist').count()
        if cnc_bks >= 10:
            min_time_bks = Backup.query.filter_by(backup_type='blacklist')\
                .order_by(Backup.created_at).limit(cnc_bks - 10).all()
            
            for min_time_bk in min_time_bks:
                remove_file(min_time_bk.path)
                db.session.delete(min_time_bk)
            
        db.session.add(bk)
        db.session.commit()
        return True, None
    