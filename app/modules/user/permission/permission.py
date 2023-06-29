from app import db
from app.modules.common.model import Model


class Permission(Model):
    '''Bảng này xem xét xem có cần dùng hay ko

    Khi cần phân quyền:
        + admin
        + normal user
    '''
    __tablename__ = 'permission'

    id = db.Column(db.Integer, primary_key=True)
    permission_name = db.Column(db.String, required=True)
    description = db.Column(db.String)
