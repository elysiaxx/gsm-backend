from flask_restx import Namespace, fields

from .uricontent.uricontent import UriContent
from .content.content import Content
from .protected_content.protected_content import ProtectedContent

from .pkt_data.pkt_data import PktData
from .file_data.file_data import FileData
from .base64.base64 import Base64


class Detection:
    
    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            content = Content(self.api)
            protected_content = ProtectedContent(self.api)
            uri_content = UriContent(self.api)

            file_data = FileData(self.api)
            pkt_data = PktData(self.api)
            base64 = Base64(self.api)

            self.request = self.api.model('detection_request', {
                "content": fields.List(fields.Nested(content.request)),
                "protected_content": fields.List(fields.Nested(protected_content.request)),
                "http_encode": fields.String(required=False),

                "uricontent": fields.Nested(uri_content.request),
                'urilen': fields.String(required=False),
                "prce": fields.String(required=False),
                "pkt_data": fields.List(fields.Nested(pkt_data.request)),
                "file_data": fields.List(fields.Nested(file_data.request)),
                
                "base64": fields.List(fields.Nested(base64.request)),
                "byte_test": fields.String(required=False),
                "byte_jump": fields.String(required=False),
                "byte_extract": fields.String(required=False),

                "byte_math": fields.String(required=False),
                "ftpbounce": fields.Boolean(required=False, default=False),
                "asn1": fields.String(required=False),
                "cvs": fields.String(required=False)
            })

            self.response = {
                "content": fields.List(fields.Nested(content.response)),
                "protected_content": fields.List(fields.Nested(protected_content.response)),
                "http_encode": fields.String(required=False),

                "uricontent": fields.List(fields.Nested(uri_content.response)),
                'urilen': fields.String(required=False),
                "isdataat": fields.String(required=False),
                
                "prce": fields.String(required=False),
                "pkt_data": fields.List(fields.Nested(pkt_data.response)),
                "file_data": fields.List(fields.Nested(file_data.response)),

                "base64": fields.List(fields.Nested(base64.response)),
                "byte_test": fields.String(required=False),
                "byte_jump": fields.String(required=False),
                "byte_extract": fields.String(required=False),
                
                "byte_math": fields.String(required=False),
                "ftpbounce": fields.Boolean(required=False),
                "asn1": fields.String(required=False),
                "cvs": fields.String(required=False)
            }
        else:
            raise Exception('Param must be api namespace')

    