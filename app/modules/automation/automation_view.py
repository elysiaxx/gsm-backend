from flask_restx import Resource
from flask import request

from app.modules.automation.automation_dto import AutomationDto
from app.modules.automation.automation_controller import AutomationController
from app.modules.auth.decorator import token_required, admin_token_required

api = AutomationDto.api

action_request = AutomationDto.model_action_request
action_response = AutomationDto.model_action_response

sender_request = AutomationDto.model_sender
sender_response = AutomationDto.model_sender

send_test_request = AutomationDto.model_send_test_request

pagination = api.parser()
pagination.add_argument('page', type=int, location='args')
pagination.add_argument('pageSize', type=int, location='args')


@api.route('/action')
class ActionList(Resource):
    @api.expect(pagination)
    @api.response(code=200, model=action_response, description='')
    def get(self):
        '''
        Get action information
        
        :return: list action
        '''
        args = pagination.parse_args()
        controller = AutomationController()
        return controller.get(args=args)
    
    @token_required
    @api.expect(action_request)
    @api.response(code=200, model=action_response, description='')
    def post(self):
        '''
        Create action
        
        :return: action information if created successfully and vice versa
        '''
        data = api.payload
        controller = AutomationController()
        return controller.create(data=data, req=request)
    

@api.route('/action/<int:id>')
class Action(Resource):
    
    @api.response(code=200, model=action_response, description='')
    def get(self, id):
        '''
        Get action information
        
        :param id: action ID
        
        :return: action information
        '''
        controller = AutomationController()
        return controller.get_by_id(object_id=id)
    
    @token_required
    @api.expect(action_request)
    @api.response(code=200, model=action_response, description='')
    def put(self, id):
        '''
        Update action information
        
        :param id: action ID
        
        :return: action information
        '''
        data = api.payload
        controller = AutomationController()
        return controller.update(object_id=id, data=data, req=request)
    
    @token_required
    def delete(self, id):
        '''
        Delete action
        
        :param id: action ID
        
        :return: True if deleted successfully and vice versa
        '''
        controller = AutomationController()
        return controller.delete(object_id=id)
    

@api.route('/sender')
class Sender(Resource):
    
    @token_required
    @api.response(code=200, model=sender_response, description='')
    def get(self):
        '''
        Get sender of system
        
        :return: sender
        '''
        controller = AutomationController()
        return controller.get_sender()
    
    @token_required
    @api.expect(sender_request)
    @api.response(code=200, model=sender_response, description='')
    def put(self):
        '''
        Set sender of system
        
        :return: True if successfully and vice versa
        '''
        data = api.payload
        controller = AutomationController()
        return controller.set_sender(data=data, req=request)
    
    
@api.route('/sender/connect')
class SenderConnect(Resource):
    @token_required
    @api.expect(sender_request)
    @api.response(code=200, description='')
    def post(self):
        '''
        Test sender connection
        
        :return: True if connected successfully and vice versa
        '''
        data = api.payload
        controller = AutomationController()
        return controller.test_connection(data=data)
    
@api.route('/sender/send_test')
class SendTestEmail(Resource):
    @token_required
    @api.expect(send_test_request)
    @api.response(code=200, description='')
    def post(self):
        '''
        Send an email for testing automation service
        
        :return: True if successfully and vice versa
        '''
        data = api.payload
        controller = AutomationController()
        return controller.send_test(data=data)