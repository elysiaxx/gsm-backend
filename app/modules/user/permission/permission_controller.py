from app.modules.common.controller import Controller
from app.modules.user.permission.permission import Permission


class PermissionController(Controller):
    def create(self, data):
        pass

    def get(self):
        pass

    def update(self, object_id, data):
        pass

    def delete(self, object_id):
        pass

    def _parse_permission(self, data, permission=None):
        if permission is None:
            permission = Permission()
        if 'permission_name' in data:
            permission.permission_name = data['permission_name']
        if 'description' in data:
            permission.description = data['description']
        return permission
