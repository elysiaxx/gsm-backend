from flask_restx import Namespace, fields

from ..content.content import Content
from ..protected_content.protected_content import ProtectedContent
from ..uricontent.uricontent import UriContent


class PktData:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            content = Content(self.api)
            protected_content = ProtectedContent(self.api)
            uricontent = UriContent(self.api)
            
            self.request = self.api.model('pkt_data_request', {
                'content': fields.Nested(content.request),
                'prce': fields.String(required=False),
                'protected_content': fields.Nested(protected_content.request),
                'uricontent': fields.Nested(uricontent.request)
            })
            
            self.response = self.api.model('pkt_data_response', {
                'content': fields.Nested(content.response),
                'prce': fields.String(required=False),
                'protected_content': fields.Nested(protected_content.response),
                'uricontent': fields.Nested(uricontent.response)
            })

        else:
            raise Exception('Param must be an api namespace')