from flask_restx import Namespace, fields

from ..content.content import Content
from ..protected_content.protected_content import ProtectedContent
from ..uricontent.uricontent import UriContent


class Base64:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            content = Content(self.api)
            pcontent = ProtectedContent(self.api)
            ucontent = UriContent(self.api)
            
            self.request = self.api.model('base64_request', {
                'base64_decode': fields.String(required=False),
                'content': fields.Nested(content.request),
                
                'protected_content': fields.Nested(pcontent.request),
                'uricontent': fields.Nested(ucontent.request)
            })
            
            self.response = self.api.model('base64_response', {
                'base64_decode': fields.String(required=False),
                'content': fields.Nested(content.request),
                
                'protected_content': fields.Nested(pcontent.request),
                'uricontent': fields.Nested(ucontent.request)
            })
            
        else:
            raise Exception('Param must be an api namespace')