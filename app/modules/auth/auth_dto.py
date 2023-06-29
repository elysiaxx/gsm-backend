from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class AuthDto(Dto):
    name = 'auth'
    api = Namespace(name)

    model_login = api.model('login', {
        'email': fields.String(required=True),
        'password': fields.String(requried=True)
    })

    message_response = api.model('response', {
        'message': fields.String(required=True)
    })
