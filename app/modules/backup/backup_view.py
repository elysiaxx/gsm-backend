from flask import request
from flask_restx import Resource

from app.modules.backup.backup_dto import BackupDto
from app.modules.backup.backup_controller import BackupController
from app.modules.auth.decorator import token_required, admin_token_required


api = BackupDto.api

backup_request = BackupDto.model_request
backup_response = BackupDto.model_response

pagination = api.parser()
pagination.add_argument('page', type=int, required=False, location='args')
pagination.add_argument('pageSize', type=int, required=False, location='args')

get_backup = pagination.copy()
get_backup.add_argument('type', type=str, required=False, location='args')


@api.route('')
class BackupList(Resource):
    
    @token_required
    @api.expect(get_backup)
    @api.response(code=200, model=backup_response, description='')
    def get(self):
        '''
        Get all backup information
        
        :return: list backup 
        '''
        args = get_backup.parse_args()
        controller = BackupController()
        return controller.get(args=args)
    
    @token_required
    @api.expect(backup_request)
    @api.response(code=200, model=backup_response, description='')
    def post(self):
        '''
        Create backup.
        -------------------
        All data to create a new backup is stored in dictionary form.

        :return: New backup is created successfully and error vice versa.
        '''
        data = api.payload
        controller = BackupController()
        return controller.create(data=data, req=request)
    

@api.route('/<int:id>')
class Backup(Resource):
    
    @token_required
    @api.response(code=200, model=backup_response, description='')
    def get(self, id):
        '''
        Get backup information with backup ID
        
        :param id: backup ID
        
        :return: backup information 
        '''
        controller = BackupController()
        return controller.get_by_id(object_id=id)
    
    @token_required
    @api.response(code=200, description='')
    def delete(self, id):
        '''
        Delete backup with backup ID
        
        :param id: backup ID
        
        :return: True if successfully and vice versa
        '''
        controller = BackupController()
        return controller.delete(object_id=id)
        

@api.route('/restore/<int:id>')
class Restore(Resource):
    
    @token_required
    @api.response(code=200, description='')
    def get(self, id):
        '''
        Restore backup
        -----------------------
        
        :return: retore rule file if restored successfully and error vice versa.
        '''
        controller = BackupController()
        return controller.restore_by_id(object_id=id, req=request)
    
    