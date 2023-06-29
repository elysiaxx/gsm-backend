from flask_restx import Namespace, fields

class DetectionFilter:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            self.request = self.api.model('detection_filter_request', {
                "track": fields.String(required=True),
                "count": fields.Integer(required=True, min=0),
                "seconds": fields.Integer(required=True, min=0),
            })
            
            self.response = self.api.model('detection_filter_response', {
                "track": fields.String(required=True),
                "count": fields.Integer(required=True),
                "seconds": fields.Integer(required=True),
            })
        else:
            raise Exception('Param must be an api namespace')