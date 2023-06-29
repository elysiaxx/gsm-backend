from flask_restx import Namespace, fields

from .detection_filter.detection_filter import DetectionFilter


class PostDetection:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            detection_filter = DetectionFilter(self.api)
            self.request = self.api.model('post_detection_request', {
                "logto": fields.String(required=False),
                "session": fields.String(required=False),

                # "resp": fields.String(required=False),
                # "react": fields.String(required=False),

                "tag": fields.String(required=False),
                # "replace": fields.String(required=False),
                "detection_filter": fields.Nested(detection_filter.request)
            })

            self.response = self.api.model('post_detection_response', {
                "logto": fields.String(required=False),
                "session": fields.String(required=False),

                # "resp": fields.String(required=False),
                # "react": fields.String(required=False),

                "tag": fields.String(required=False),
                # "replace": fields.String(required=False),
                "detection_filter": fields.Nested(detection_filter.response)
            })
        else:
            raise Exception('Param must be an api namespace')
