from flask_restx import Namespace, fields

from .modifier.modifier import Modifier


class Content:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            modifier = Modifier(self.api)
            self.request = self.api.model('content_request', {
                'content': fields.String(required=False),
                'negative': fields.Boolean(required=False, default=False),
                'modifiers': fields.Nested(modifier.request)
            })

            self.response = ('content_response', {
                'content': fields.String(required=False),
                'negative': fields.Boolean(required=False),
                'modifiers': fields.Nested(modifier.response)
            })

        else:
            raise Exception('Param must be api namespace')