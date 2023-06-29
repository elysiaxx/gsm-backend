import os

import dateutil.parser
from flask import request, send_file, url_for
from flask_restx import marshal

from app import db
from app.modules.auth.auth_controller import AuthController
from app.modules.common.controller import Controller
from app.modules.user.user import User
from app.modules.user.user_dto import UserDto
from settings.config import Config
from utils.response import send_error, send_result
from utils.util import encode_file_name

AVATAR_FOLDER = Config.AVATAR_FOLDER
STATIC_FOLDER = Config.STATIC_FOLDER
IMAGE_FOLDER = Config.IMAGE_FOLDER


class UserController(Controller):

    def create(self, data):
        '''
        Create new user

        :param data: this is data to create new user (in dictionary format)

        :return: Return user if create successfully and vise versa.
        '''
        if not isinstance(data, dict):
            return send_error(message="Data is not correct or not in dictionary type")
        if not 'email' in data and not 'password' in data:
            return send_error(message="Please fill email and password")
        try:
            exist_user = User.query.filter_by(email=data['email']).first()
            if not exist_user:
                user = self._parse_user(data, None)
                db.session.add(user)
                db.session.commit()
                return send_result(message='User was created successfully', data=marshal(user, UserDto.model_response))
            else:
                return send_error(message='User exists')
        except Exception as e:
            print(e.__str__())
            return send_error(message='Could not create user. Check again')

    def get(self):
        '''
        Get all users in the system.

        :return: List of users.
        '''
        try:
            users = User.query.all()
            return send_result(data=marshal(users, UserDto.model_response), message='Success')
        except Exception as e:
            print(e.__str__())
            return send_error("Could not load error, please try again later.")

    def get_by_id(self, object_id):
        '''
        Get user by ID

        :param object_id: The user id

        :return: The user if found and None vice versa.
        '''
        if object_id is None:
            return send_error(message="The user ID must not be null.")
        try:
            user = User.query.filter_by(id=object_id).first()
            if user is None:
                return send_error(data="Could not find user by this id")
            else:
                # when call to this function, increase the profile_views
                user.profile_views += 1
                db.session.commit()
                return send_result(data=marshal(user, UserDto.model_response))
        except Exception as e:
            print(e.__str__())
            return send_error(message='Could not get user by ID {}.'.format(object_id))

    def update(self, object_id, data):
        '''
        Update user.

        Doest now allow to update `id`, `email`, `password`.

        :param object_id:

        :param data:

        :return:
        '''
        if not isinstance(data, dict):
            return send_error(message='You must pass dictionary-like data.')
        if 'id' in data:
            return send_error(message='Could not update ID.')
        if 'email' in data:
            return send_error(message='Email update is not allowed here.')
        if 'password' in data and data['password'] is None:
            return send_error(message='Password update is now allowed here.')
        try:
            user = User.query.filter_by(id=object_id).first()
            if not user:
                return send_error(message='User not found')
            else:
                user = self._parse_user(data=data, user=user)
                db.session.commit()
                return send_result(message='Update successfully', data=marshal(user, UserDto.model_response))
        except Exception as e:
            print(e.__str__())
            return send_error(message='Could not update user')

    def delete(self, object_id):
        '''
        Delete user from the system.

        :param object_id:

        :return:
        '''
        try:
            user = User.query.filter_by(id=object_id).first()
            if not user:
                return send_error(message='User not found')
            else:
                db.session.delete(user)
                db.session.commit()
                return send_result(message='User was deleted successfully')
        except Exception as e:
            print(e.__str__())
            return send_error(message='Could not delete user')

    def upload_avatar(self, args):
        '''
        Upload avatar.

        :param args:
        :return:
        '''
        if not isinstance(args, dict) or not 'avatar' in args:
            return send_error(message='Your request does not contain avatar.')
        # upload here
        user, message = AuthController.get_logged_user(request)
        # user = User.query.filter_by(id=id).first()
        if user is None:
            return send_error(message)

        photo = args['avatar']
        if photo:
            file_name = 'user_' + str(user.id) + '_avatar'
            file_name = encode_file_name(file_name) + ".png"
            try:
                if not os.path.exists(STATIC_FOLDER):
                    os.mkdir(STATIC_FOLDER)
                if not os.path.exists(IMAGE_FOLDER):
                    os.mkdir(IMAGE_FOLDER)
                if not os.path.exists(AVATAR_FOLDER):
                    os.mkdir(AVATAR_FOLDER)
                photo.save(os.path.join(AVATAR_FOLDER, file_name))
                user.profile_pic_url = url_for('user_avatar', filename=file_name)
                db.session.commit()
                return send_result(data=marshal(user, UserDto.model_response), message='Upload avatar successfully.')
            except Exception as e:
                print(e.__str__())
                return send_error(message='Could not save your avatar.')
        else:
            return send_error(message='Please attach or check your photo before uploading.')

    def get_avatar(self):
        user, message = AuthController.get_logged_user(request)
        # user = User.query.filter_by(id=id).first()
        if user is None:
            return send_error(message)
        file_name = 'user_' + str(user.id) + '_avatar'
        filename = encode_file_name(file_name) + ".png"
        # filename = request.args.get('filename')
        filename = os.path.join(AVATAR_FOLDER, filename)
        if os.path.exists(filename):
            return send_file(filename)
        else:
            return send_error(message='Avatar does not exist. Upload it first.')

    def _parse_user(self, data, user=None):
        if user is None:
            user = User()
        if 'display_name' in data:
            user.display_name = data['display_name']
        if 'title' in data:
            user.title = data['title']

        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'middle_name' in data:
            user.middle_name = data['middle_name']
        if 'last_name' in data:
            user.last_name = data['last_name']

        if 'gender' in data:
            user.gender = data['gender']
        if 'age' in data:
            user.age = data['age']
        if 'email' in data:
            user.email = data['email']
        if 'password' in data:
            user.set_password(password=data['password'])

        if 'last_seen' in data:
            try:
                user.last_seen = dateutil.parser.isoparse(data['last_seen'])
            except Exception as e:
                print(e.__str__())
                pass
        if 'joined_date' in data:
            try:
                user.joined_date = dateutil.parser.isoparse(data['joined_date'])
            except Exception as e:
                print(e.__str__())
                pass
        if 'confirmed' in data:
            try:
                user.confirmed = bool(data['confirmed'])
            except Exception as e:
                print(e.__str__())
                pass
        if 'profile_pic_url' in data:
            user.profile_pic_url = data['profile_pic_url']
        if 'profile_pic_data_url' in data:
            user.profile_pic_data_url = data['profile_pic_data_url']
        if 'admin' in data:
            try:
                user.admin = bool(data['admin'])
            except Exception as e:
                print(e.__str__())
                pass
        if 'active' in data:
            try:
                user.active = bool(data['active'])
            except Exception as e:
                print(e.__str__())
                pass
        return user
