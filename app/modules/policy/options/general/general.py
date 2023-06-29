from flask_restx import Namespace, fields


class General:
    request = {
        "msg": fields.String(required=False),
        "reference": fields.List(fields.String),
        "gid": fields.Integer(required=True, min=0),
        "sid": fields.Integer(required=True, min=0),

        "rev": fields.Integer(required=False, min=0),
        "classtype": fields.String(required=True),
        "priority": fields.Integer(required=False, default=3),
        "metadata": fields.List(fields.String)
    }

    response = {
        "msg": fields.String(required=False),
        "reference": fields.List(fields.String),
        "gid": fields.Integer(required=False),
        "sid": fields.Integer(required=False),

        "rev": fields.Integer(required=False),
        "classtype": fields.String(required=False),
        "priority": fields.Integer(required=False),
        "metadata": fields.List(fields.String)
    }