from flask_restx import Namespace, fields


class Modifier:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            self.request = self.api.model('modifier_request', {
                "nocase": fields.Boolean(required=False, default=False),
                "rawbytes": fields.Boolean(required=False, default=False),
                "depth": fields.Integer(required=False, min=0),

                "offset": fields.Integer(required=False, min=0),
                "distance": fields.Integer(required=False, min=0),
                "within": fields.Integer(required=False, min=0),
                "http_client_body": fields.Boolean(required=False, default=False),

                "http_cookie": fields.Boolean(required=False, default=False),
                "http_raw_cookie": fields.Boolean(required=False, default=False),
                "http_header": fields.Boolean(required=False, default=False),
                "http_raw_header": fields.Boolean(required=False, default=False),

                "http_method": fields.Boolean(required=False, default=False),
                "http_uri": fields.Boolean(required=False, default=False),
                "http_raw_uri": fields.Boolean(required=False, default=False),

                "http_stat_code": fields.Boolean(required=False, default=False),
                "http_stat_msg": fields.Boolean(required=False, default=False),
                "fast_pattern": fields.String(required=False)
            })

            self.response = self.api.model('modifier_response', {
                "nocase": fields.Boolean(required=False),
                "rawbytes": fields.Boolean(required=False),
                "depth": fields.Integer(required=False),

                "offset": fields.Integer(required=False),
                "distance": fields.Integer(required=False),
                "within": fields.Integer(required=False),
                "http_client_body": fields.Boolean(required=False),

                "http_cookie": fields.Boolean(required=False),
                "http_raw_cookie": fields.Boolean(required=False),
                "http_header": fields.Boolean(required=False),
                "http_raw_header": fields.Boolean(required=False),

                "http_method": fields.Boolean(required=False),
                "http_uri": fields.Boolean(required=False),
                "http_raw_uri": fields.Boolean(required=False),
                
                "http_stat_code": fields.Boolean(required=False),
                "http_stat_msg": fields.Boolean(required=False),
                "fast_pattern": fields.String(required=False)
            })

        else:
            raise Exception('Param must be an api namespace')