from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class UserDto(Dto):
    name = 'user'
    api = Namespace(name)
    model_request = api.model('user_request', {
        'display_name': fields.String(required=False, default=''),
        'title': fields.String(required=False, default=''),

        'first_name': fields.String(required=False, default=''),
        'middle_name': fields.String(required=False, default=''),
        'last_name': fields.String(required=False, default=''),

        'gender': fields.String(required=False, default=''),
        'age': fields.String(required=False, default=''),
        'email': fields.String(required=True),
        'password': fields.String(required=True),

        'profile_pic_url': fields.String(required=False, default=''),
        'profile_pic_data_url': fields.String(required=False, default=''),
        'admin': fields.Boolean(required=False, default=False),
        'active': fields.Boolean(required=False, default=False)
    })

    model_response = api.model('user_response', {
        'id': fields.Integer(readonly=True),
        'display_name': fields.String(required=False),
        'title': fields.String(required=False),

        'first_name': fields.String(required=False),
        'middle_name': fields.String(required=False),
        'last_name': fields.String(required=False),

        'gender': fields.String(required=False),
        'age': fields.String(required=False),
        'email': fields.String(required=False),
        # 'password': fields.String(required=False),

        'last_seen': fields.DateTime(required=False),
        'joined_date': fields.DateTime(required=False),
        'confirmed': fields.Boolean(required=False),

        'profile_pic_url': fields.String(required=False),
        'profile_pic_data_url': fields.String(required=False),
        'admin': fields.Boolean(required=False),
        'active': fields.Boolean(required=False)
    })
