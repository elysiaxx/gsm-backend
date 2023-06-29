from flask_restx import Namespace, fields

from .modifier.modifier import Modifier


class ProtectedContent:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            modifier = Modifier(self.api)
            self.request = self.api.model('protected_content_request', {
                'protected_content': fields.String(required=False),
                'negative': fields.Boolean(required=False, default=False),
                'modifiers': fields.Nested(modifier.request)
            })

            self.response = self.api.model('protected_content_response', {
                'protected_content': fields.String(required=False),
                'negative': fields.Boolean(required=False),
                'modifiers': fields.Nested(modifier.request)
            })

        else:
            raise Exception('Param must be an api namespace')