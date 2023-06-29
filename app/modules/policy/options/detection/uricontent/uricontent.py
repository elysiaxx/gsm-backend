from flask_restx import Namespace, fields

from .modifier.modifier import Modifier


class UriContent:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            modifier = Modifier(self.api)
            self.request = self.api.model('uricontent_request', {
                'uricontent': fields.String(required=False),
                'negative': fields.Boolean(required=False, default=False),
                'modifiers': fields.Nested(modifier.request),
            })

            self.response = self.api.model('uricontent_response', {
                'uricontent': fields.String(required=False),
                'negative': fields.Boolean(required=False),
                'modifiers': fields.Nested(modifier.request),
            })
        else:
            raise Exception('Param must be an api namespace')
