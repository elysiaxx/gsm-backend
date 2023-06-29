from flask_restx import Resource

from app.modules.auth.decorator import token_required, admin_token_required
from app.modules.log.log_controller import LogController
from app.modules.log.log_dto import LogDto

api = LogDto.api

log_response = LogDto.model_response

log_request = api.parser()
log_request.add_argument('limit', type=int, required=False, location='args')


@api.route('')
class LogView(Resource):
    
    @token_required
    @api.expect(log_request)
    @api.response(code=200, model=log_response, description='')
    def get(self):
        '''
        Get log infos
        
        :return: log infos
        '''
        args = log_request.parse_args()
        controller = LogController()
        return controller.get(args=args)