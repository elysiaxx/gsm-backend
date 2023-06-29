from flask_restx import marshal
from app import db
from datetime import datetime

from app.modules.auth.auth_controller import AuthController
from app.modules.setup.setting import Setting
from app.modules.setup.setting_dto import SettingDto

from utils.message_code import ErrorCode
from utils.response import send_error, send_result
from utils.util import check_setup_state


class SettingController():
    
    def get_backup(self):
        '''
        Get backup setup info
        -------------------------------
        
        :return: info
        '''
        try:
            sbk = Setting.query.filter_by(setting_type='backup').first()
            if not sbk:
                return send_error(code=ErrorCode.NOT_FOUND, message='Setting not found')
            
            return send_result(code=200, data=marshal(sbk, SettingDto.model_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def setup_backup(self, data, req):
        '''
        Set up backup
        
        :return: True if successfully and vice versa
        '''
        if not isinstance(data, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data must be an instance of directory')
        if 'state' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have state field')
        if 'options_type' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request does not have options_type field') 
        
        try:
            user, message = AuthController.get_logged_user(req=req)
            if not user:
                return send_error(code=ErrorCode.BAD_REQUEST, message=message)
            
            setting = Setting.query.filter_by(setting_type='backup').first()
            if not setting:
                return send_error(code=ErrorCode.NOT_FOUND, message='Setting not found')
            
            if check_setup_state(data['state']) is False:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Options field is invalid')
            
            setting = self._parse_setting(data, setting)
            setting.setup_at = str(datetime.now())
            setting.setup_by = user.email
            
            db.session.commit()
            return send_result(code=200, data=marshal(setting, SettingDto.model_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def _parse_setting(self, data, setting):
        if setting is None:
            setting = Setting()
            
        if 'state' in data:
            setting.state = data['state']
        if 'options_type' in data:
            setting.options_type = data['options_type']
            
        return setting
        