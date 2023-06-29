from flask import request
from flask_restx import Resource
from werkzeug.datastructures import FileStorage

from app.modules.cnc.cnc_dto import CncDto
from app.modules.cnc.cnc_controller import CncController
from app.modules.auth.decorator import token_required, admin_token_required

api = CncDto.api

cnc_server_request = CncDto.model_request
cnc_server_response = CncDto.model_response

pagination = api.parser()
pagination.add_argument('page', type=int, required=False, location='args')
pagination.add_argument('pageSize', type=int, required=False, location='args')
pagination.add_argument('type', type=str, required=False, location='args')

cnc_upload = api.parser()
cnc_upload.add_argument('file', type=FileStorage, location='files', required=True)
cnc_upload.add_argument('overwrite', type=bool, location='args', required=True)

@api.route('')
class CncList(Resource):
    @token_required
    @api.expect(pagination)
    @api.response(code=200, model=cnc_server_response, description='')
    def get(self):
        '''
        Get all cnc server in the system
        
        :return: list cnc server
        '''
        args = pagination.parse_args()
        controller = CncController()
        return controller.get(args=args)
    
    @token_required
    @api.expect(cnc_server_request)
    @api.response(code=200, model=cnc_server_response, description='')
    def post(self):
        '''
        Add cnc server into the system
        
        :return: cnc server added info
        '''
        data = api.payload
        controller = CncController()
        return controller.create(data=data, req=request)
    

@api.route('/<int:id>')
class CncServer(Resource):
    @token_required
    @api.response(code=200, model=cnc_server_response, description='')
    def get(self, id):
        '''
        Get cnc server by ID
        
        :param id: cnc server ID
        
        :return: cnc server info
        '''
        controller = CncController()
        return controller.get_by_id(object_id=id)
    
    @token_required
    @api.expect(cnc_server_request)
    @api.response(code=200, model=cnc_server_response, description='')
    def put(self, id):
        '''
        Update cnc server info
        
        :return: 
        '''
        data = api.payload
        controller = CncController()
        return controller.update(object_id=id, data=data, req=request)
        
    @token_required
    def delete(self, id):
        '''
        Delete cnc server info
        
        :return: True if successfully and vice versa
        '''
        controller = CncController()
        return controller.delete(object_id=id)
    

@api.route('/upload')
class CncUpload(Resource):
    
    @token_required
    @api.expect(cnc_upload)
    @api.response(code=200, model=cnc_server_response, description='')
    def post(self):
        '''
        Upload cnc file
        
        :return: list cnc info
        '''
        args = cnc_upload.parse_args()
        print(args)
        controller = CncController()
        return controller.upload(args=args, req=request)