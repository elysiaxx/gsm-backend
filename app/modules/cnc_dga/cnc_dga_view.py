from flask_restx import Resource, inputs

from app.modules.cnc_dga.cnc_dga_dto import CncDgaDto
from app.modules.cnc_dga.cnc_dga_controller import CncDgaController
from app.modules.auth.decorator import token_required, admin_token_required

api = CncDgaDto.api

cnc_dga_request = CncDgaDto.model_request
cnc_dga_response = CncDgaDto.model_response

pagination = api.parser()
pagination.add_argument('page', type=int, required=False, location='args')
pagination.add_argument('pageSize', type=int, required=False, location='args')

filter = pagination.copy()
filter.add_argument('domain', type=str, required=False, location='form')
filter.add_argument('first', type=inputs.datetime_from_iso8601, location='form')
filter.add_argument('last', type=inputs.datetime_from_iso8601, location='form')

@api.route('')
class CncDgaList(Resource):
    @token_required
    @api.expect(pagination)
    @api.response(code=200, model=cnc_dga_response, description='')
    def get(self):
        '''
        Get all cnc dga alert
        
        :return: list cnc dga alert
        '''
        args = pagination.parse_args()
        controller = CncDgaController()
        return controller.get(args=args)
    
@api.route('/filter')
class CncDgaFilter(Resource):
    @token_required
    @api.expect(filter)
    @api.response(code=200, model=cnc_dga_response, description='')
    def post(self):
        '''
        Filter cnc dga alert
        '''
        args = filter.parse_args()
        controller = CncDgaController()
        return controller.filter(args=args)
