from flask_restx import Namespace, fields


class NonDetection:

    def __init__(self, api):
        if type(api) is type(Namespace('test')):
            self.api = api
            self.request = self.api.model('non_detection_request', {
                "fragoffset": fields.String(required=False),
                "ttl": fields.String(required=False),
                "tos": fields.String(required=False),

                "id": fields.Integer(required=False),
                "ipopts": fields.String(required=False),
                "fragbits": fields.String(required=False),
                "dsize": fields.String(required=False),

                "flags": fields.String(required=False),
                "flow": fields.String(required=False),
                "flowbits": fields.List(fields.String),
                "seq": fields.Integer(required=False),

                "ack": fields.Integer(required=False),
                "windows": fields.String(required=False),
                "itype": fields.String(required=False),
                "icode": fields.String(required=False),

                "icmp_id": fields.Integer(required=False),
                "icmp_seq": fields.Integer(required=False, min=0),
                "rpc": fields.String(required=False),
                "ip_proto": fields.String(required=False),

                "sameip": fields.Boolean(required=False, default=False),
                "stream_reassemble": fields.String(required=False),
                "stream_size": fields.String(required=False),
            })

            self.response = self.api.model('non_detection_response', {
                "fragoffset": fields.String(required=False),
                "ttl": fields.String(required=False),
                "tos": fields.String(required=False),

                "id": fields.Integer(required=False),
                "ipopts": fields.String(required=False),
                "fragbits": fields.String(required=False),
                "dsize": fields.String(required=False),

                "flags": fields.String(required=False),
                "flow": fields.String(required=False),
                "flowbits": fields.List(fields.String),
                "seq": fields.Integer(required=False, min=0),

                "ack": fields.Integer(required=False, min=0),
                "windows": fields.String(required=False),
                "itype": fields.String(required=False),
                "icode": fields.String(required=False),

                "icmp_id": fields.Integer(required=False, min=0),
                "icmp_seq": fields.Integer(required=False, min=0),
                "rpc": fields.String(required=False),
                "ip_proto": fields.String(required=False),

                "sameip": fields.Boolean(required=False, default=False),
                "stream_reassemble": fields.String(required=False),
                "stream_size": fields.String(required=False),
            })
        else:
            raise Exception('Param must be an api namespace')
