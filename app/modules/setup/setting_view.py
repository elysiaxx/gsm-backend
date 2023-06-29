from flask import request
from flask_restx import Resource
from app.modules.setup.setting_controller import SettingController

from app.modules.setup.setting_dto import SettingDto
from app.modules.auth.decorator import token_required, admin_token_required

api = SettingDto.api

backup_request = SettingDto.model_backup_request
settup_response = SettingDto.model_response


@api.route('/backup')
class Backup(Resource):
    
    @token_required
    @api.response(code=200, model=settup_response, description='')
    def get(self):
        '''
        Get backup setup information
        --------------------------
        
        :return: info
        '''
        controller = SettingController()
        return controller.get_backup()
    
    @admin_token_required
    @api.expect(backup_request)
    @api.response(code=200, model=settup_response, description='')
    def put(self):
        '''
        Set up backup
        
        :return: settup info if successfully and vice versa
        '''
        data = api.payload
        controller = SettingController()
        return controller.setup_backup(data=data, req=request)
        
