from flask_restx import Namespace, fields

from app.modules.common.dto import Dto

class Header:
    request = {
        "action": fields.String(required=True),
        "protocol": fields.String(required=True),
        "source_ip": fields.String(required=True),

        "source_port": fields.String(required=True),
        "direction": fields.String(required=True),
        "dest_ip": fields.String(required=True),
        "dest_port": fields.String(required=True)
    }

    response = {
        "action": fields.String(required=False),
        "protocol": fields.String(required=False),
        "source_ip": fields.String(required=False),

        "source_port": fields.String(required=False),
        "direction": fields.String(required=False),
        "dest_ip": fields.String(required=False),
        "dest_port": fields.String(required=False)
    }