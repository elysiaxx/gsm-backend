from flask_restx import Namespace,fields

from app.modules.common.dto import Dto

class SignatureDto(Dto):
    name = 'signature'
    api = Namespace(name)

    model_response = api.model('signature_response',{
        'sig_id': fields.Integer(required=False),
        'sig_name': fields.Integer(required=False),
        'sig_class_id': fields.Integer(required=False),
        'sig_priority': fields.Integer(required=False),
        'sig_rev': fields.Integer(required=False),
        'sig_sid': fields.Integer(required=False),
        'sig_gid': fields.Integer(required=False)
    })