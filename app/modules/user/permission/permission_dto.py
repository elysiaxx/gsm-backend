from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class PermissionDto(Dto):
    name = 'permission'
    api = Namespace(name)
    model = api.model('permission', {
        'permission_name': fields.String(required=False, default=''),
        'description': fields.String(required=False, default='')
    })
