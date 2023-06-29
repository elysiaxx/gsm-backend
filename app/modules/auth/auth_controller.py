from datetime import datetime

from flask_restx import marshal

from app import db
from app.modules.user.user import User
from app.modules.user.user_dto import UserDto
from settings.config import Config
from utils.response import send_result, send_error
from utils.util import encode_auth_token, decode_auth_token, log


class AuthController:
    """
    This class is used to authenticate and authorize the user.
    """

    @staticmethod
    def check_user_exist(email):
        '''
        Check user exist by its email. One email on one register
        :param email:
        :return:
        '''
        # password_hash = generate_password_hash(password=password)
        user = User.query.filter_by(email=email).first()
        if user is not None:  # user is exist.
            return True
        else:
            return False

    # @staticmethod
    def login_user(self, data):
        """
        Login user handling.
        """
        try:
            # print(data)
            user = User.query.filter_by(email=data['email']).first()
            if user and user.check_password(data['password']):
                auth_token = encode_auth_token(user_id=user.id, user_role=user.admin)
                user.active = True
                db.session.commit()
                if auth_token:
                    log("info",user.email,"Logged In")
                    return {'access_token': auth_token.decode('utf8')}
            else:
                return send_error(
                    message='Email hoac Mat khau khong dung, vui long thu lai')  # Email or Password does not match')
        except Exception as e:
            print(e.__str__())
            return send_error(
                message='Khong the dang nhap, vui long thu lai.')


    @staticmethod
    def check_token(req):
        '''
        Check token for genuine user.
        '''
        auth_token = None
        api_key = None
        # auth = False
        if 'X-API-KEY' in req.headers:
            api_key = req.headers['X-API-KEY']
        if 'Authorization' in req.headers:
            auth_token = req.headers.get('Authorization')
        if not auth_token and not api_key:
            # auth = False
            return None
        if api_key is not None:
            auth_token = api_key

        return str(auth_token).__eq__(Config.AUTH_TOKEN)

    def logout_user(self, req):
        '''
        Logout user handling.
        '''
        auth_token = None
        api_key = None
        # auth = False
        if 'X-API-KEY' in req.headers:
            api_key = req.headers['X-API-KEY']
        if 'Authorization' in req.headers:
            auth_token = req.headers.get('Authorization')
        if not auth_token and not api_key:
            # auth = False
            return None
        if api_key is not None:
            auth_token = api_key
        if auth_token:
            # get user information, check user exist
            user_id, _ = decode_auth_token(auth_token=auth_token)
            user = User.query.filter_by(id=user_id).first()
            if user is not None:
                user.active = False
                user.last_seen = datetime.now()
                db.session.commit()
            # save token to backlist.
            # save_token(token=auth_token)
            return send_result(message='You are logged out.')
            # return redirect('') # to logout page
        else:
            return send_error(message='Provide a valid auth token')

    def get_user_info(self, req):
        '''
        Get user information.

        :param req: The request to handle.

        :return:
        '''
        user, message = AuthController.get_logged_user(req=req)
        if user is None:
            return send_error(message=message)
        return send_result(data=marshal(user, UserDto.model_response), message='Success')

    @staticmethod
    def get_logged_user(req):
        '''
        User information retrieving.
        '''
        auth_token = None
        api_key = None
        # auth = False
        if 'X-API-KEY' in req.headers:
            api_key = req.headers['X-API-KEY']
        if 'Authorization' in req.headers:
            auth_token = req.headers.get('Authorization')
        if not auth_token and not api_key:
            # auth = False
            return None, 'You must provide a valid token to continue.'
        if api_key is not None:
            auth_token = api_key
        user_id, message = decode_auth_token(auth_token=auth_token)
        if user_id is None:
            return None, message
        try:
            user = User.query.filter_by(id=user_id).first()
            return user, None
        except Exception as e:
            print(e.__str__())
            return None, message
