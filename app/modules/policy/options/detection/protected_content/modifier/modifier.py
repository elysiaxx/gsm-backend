from flask_restx import Namespace, fields

from app.modules.common.dto import Dto


class Modifier:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            self.request = self.api.model('modifier_request', {
                "hash": fields.String(required=False),
                "length": fields.Integer(required=False),
                "rawbytes": fields.Boolean(required=False, default=False),

                "offset": fields.Integer(required=False),
                "distance": fields.Integer(required=False),
                "http_client_body": fields.Boolean(required=False, default=False),
                "http_cookie": fields.Boolean(required=False, default=False),
                
                "http_raw_cookie": fields.Boolean(required=False, default=False),
                "http_header": fields.Boolean(required=False, default=False),
                "http_raw_header": fields.Boolean(required=False, default=False),
                "http_method": fields.Boolean(required=False, default=False),

                "http_uri": fields.Boolean(required=False, default=False),
                "http_raw_uri": fields.Boolean(required=False, default=False),
                "http_stat_code": fields.Boolean(required=False, default=False),
                "http_stat_msg": fields.Boolean(required=False, default=False)
            })
            
            self.response = self.api.model('modifier_response', {
                "hash": fields.String(required=False),
                "length": fields.Integer(required=False),
                "rawbytes": fields.Boolean(required=False),

                "offset": fields.Integer(required=False),
                "distance": fields.Integer(required=False),
                "http_client_body": fields.Boolean(required=False),
                "http_cookie": fields.Boolean(required=False),

                "http_raw_cookie": fields.Boolean(required=False),
                "http_header": fields.Boolean(required=False),
                "http_raw_header": fields.Boolean(required=False),
                "http_method": fields.Boolean(required=False),
                
                "http_uri": fields.Boolean(required=False),
                "http_raw_uri": fields.Boolean(required=False),
                "http_stat_code": fields.Boolean(required=False),
                "http_stat_msg": fields.Boolean(required=False)
            })

        else:
            raise Exception('Param must be an api namespace')
