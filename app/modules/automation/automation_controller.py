import os
from flask_restx import marshal
from datetime import datetime

from app import db
from app.modules.automation.automation import Automation

from app.modules.automation.action import Action
from app.modules.automation.automation_dto import AutomationDto
from app.modules.auth.auth_controller import AuthController

from utils.redis_handler import set_sender
from utils.response import send_result, send_error

from utils.message_code import ErrorCode
from utils.util import check_email, send_test_email, test_connect
from utils.message import messages

class AutomationController():
    
    def get(self, args):
        '''
        Get all action information in the system
        
        :return: list action information
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = Action.query.order_by(
                Action.created_at.desc()
            ).paginate(page=page, per_page=pageSize, error_out=False)
            
            res = {
                "page": data.page,
                "number_in_page": len(data.items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(data.items, AutomationDto.model_action_response)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def create(self, data, req):
        '''
        Create an action
        
        :param data: dictionary
        
        :param req: create request
        
        :return: action information if create sucessfully and vice versa
        '''
        if isinstance(data, dict) is False:
            return send_error(message="Data is not correct or not in dictionary type")
        if 'action_filter' not in data \
                and 'action_name' not in data \
                and 'description' not in data \
                and 'minimum_events' not in data \
                and 'during_time' not in data \
                and 'email_notification' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='data dictionary is not correct model for creating action')
        
        if data['action_filter'] not in ['high', 'medium', 'low']:
            return send_error(code=ErrorCode.BAD_REQUEST, message='action filter must be in [high, medium, low]')
        try:
            sender = Automation.query.first()
            if not sender:
                return send_error(
                    
                    code=ErrorCode.NOT_FOUND_SENDER_CREDENTIAL,
                    message=messages[str(ErrorCode.NOT_FOUND_SENDER_CREDENTIAL)]
                )
                
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(message=message)

            action = self._parse_action(data=data, action=None)
            action.created_by = user.email
            action.updated_by = user.email
            
            tmp_time = datetime.now()
            action.created_at = str(tmp_time)
            action.updated_at = str(tmp_time)
           
            db.session.add(action)
            db.session.commit()
            return send_result(code=200, data=marshal(action, AutomationDto.model_action_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def get_by_id(self, object_id):
        '''
        Get action information by action ID
        
        :param object_id: int
        
        :return: action information
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message="The action ID must not be null.")
        try:
            action = Action.query.filter_by(id=object_id).first()
            if action is None:
                return send_error(code=ErrorCode.NOT_FOUND, message="Action not found")
            
            return send_result(code=200, data=marshal(action, AutomationDto.model_action_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def update(self, object_id, data, req):
        '''
        Update action information by action ID
        
        :param object_id: action ID
        
        :param data: dictionary
        
        :param req: udpate request
        
        :return: action information if updated successfully and vice versa
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Action ID must not be null')
        if isinstance(data, dict) is False:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data is not correct or not in dictionary type')
        try:
            action = Action.query.filter_by(id=object_id).first()
            if action is None:
                return send_error(code=ErrorCode.NOT_FOUND, message='Action not found')
            
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(code=ErrorCode.NOT_FOUND, message=message)
            
            action = self._parse_action(data=data, action=action)
            action.updated_by = user.email
            action.updated_at = str(datetime.now())
            
            db.session.commit()
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def delete(self, object_id):
        '''
        Delete action by action ID
        
        :param object_id: int
        
        :return: True if deleted sucessfully and vice versa
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Action ID must not be null')
        try:
            action = Action.query.filter_by(id=object_id).first()
            if action is None:
                return send_error(code=ErrorCode.NOT_FOUND, message='Action not found')
            
            db.session.delete(action)
            db.session.commit()
            return send_result(code=200, message='Success')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def _parse_action(self, data, action=None):
        if action is None:
            action = Action()
        
        if 'action_name' in data:
            action.action_name = data['action_name']
        if 'description' in data:
            action.description = data['description']
        
        if 'action_filter' in data:
            action.action_filter = data['action_filter']
        if 'minimum_events' in data:
            action.minimum_events = data['minimum_events']
        
        if 'during_time' in data:
            action.during_time = data['during_time']
        
        if 'email_notification' in data:
            action.email_notification = data['email_notification']
            
        return action

    def get_sender(self):
        '''
        Get sender of system
        
        :return: sender info
        '''
        try:
            sender = Automation.query.first()
            data = { 
                "email" : sender.email,
                "password": sender.password
            }
            
            return send_result(code=200, data=marshal(data, AutomationDto.model_sender))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def set_sender(self, data, req):
        '''
        Set sender os system
        
        :return: sender info if sucessfully and vice versa
        '''
        if isinstance(data, dict) is False:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data is not correct or not in dictionary type')
        if 'email' not in data and 'password' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Sensor data dictionary is not correct model')
        if check_email(data['email']) is False:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Email is invalid')
        
        try:
            ok, err = test_connect(data['email'], data['password'])
            if ok is False:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            sender = Automation.query.first()
            sender.email = data['email']
            sender.password = data['password']
            
            db.session.commit()
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    def test_connection(self, data):
        '''
        Check conntection to gmail server by sender credential
        
        :param data: sender credential
        
        :return: True if successfully and vice versa
        '''
        if isinstance(data, dict) is False:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Data is not correct or not in dictionary type')
        if 'email' not in data and 'password' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Sensor data dictionary is not correct model')
        try:
            if check_email(data['email']) is False:
                return send_error(code=ErrorCode.NOT_FOUND, message='Email isn\'t exist')
            ok, err = test_connect(data['email'], data['password'])
            if ok is False:
                return send_error(code=ErrorCode.BAD_REQUEST, message=err)
            return send_result(code=200, message='OK')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def send_test(self, data):
        '''
        Send an email for testing automation service
        
        :return: True if successfully and vice versa
        '''
        if not isinstance(data, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message="Data must be an instance of dictionary")
        if 'email' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request doesn\'t have email')
        
        if 'password' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Your request doesn't have password")
        if 'recipient' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request doesn\'t have recipient')
        
        try:
            ok, err = send_test_email(data['email'], data['password'], data['recipient'])
            if not ok:
                return send_error(code=ErrorCode.BAD_REQUEST, message=err)
            
            return send_result(code=200, message='Success')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())