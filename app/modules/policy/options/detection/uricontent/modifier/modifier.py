from flask_restx import Namespace, fields


class Modifier:
    
    def __init__(self, api):
        if type(api) is type(Namespace('teset')):
            self.api = api
            self.request = self.api.model('modifier_request', {
                "nocase": fields.Boolean(required=False, default=False),
                "depth": fields.Integer(required=False, min=0),
                "offset": fields.Integer(required=False, min=0),

                "distance": fields.Integer(required=False, min=0),
                "within": fields.Integer(required=False, min=0),
                "fast_pattern": fields.String(required=False)
            })

            self.response = self.api.model('modifier_response', {
                "nocase": fields.Boolean(required=False),
                "depth": fields.Integer(required=False),
                "offset": fields.Integer(required=False),

                "distance": fields.Integer(required=False),
                "within": fields.Integer(required=False),
                "fast_pattern": fields.String(required=False)
            })

        else:
            raise Exception('Param must be an api namespace')
