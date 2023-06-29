from flask_restx import Resource, inputs

from app.modules.auth.decorator import token_required, admin_token_required
from app.modules.statistic.ai_events.ai_events_controller import AIEventsController
from app.modules.statistic.ai_events.ai_events_dto import AIEventsDto

api = AIEventsDto.api

ai_events_response = AIEventsDto.model_response

pagination = api.parser()
pagination.add_argument('page', type=int, required=False, location='args')
pagination.add_argument('pageSize', type=int, required=False, location='args')

ai_events_filter = api.parser()
ai_events_filter.add_argument('page', type=int, required=False, location='form')
ai_events_filter.add_argument('pageSize', type=int, required=False, location='form')

ai_events_filter.add_argument('src_ip', type=str, required=False, location='form')
ai_events_filter.add_argument('src_port', type=int, required=False, location='form')
ai_events_filter.add_argument('dst_ip', type=str, required=False, location='form')

ai_events_filter.add_argument('dst_port', type=int, required=False, location='form')
ai_events_filter.add_argument('protocol', type=str, required=False, location='form')
ai_events_filter.add_argument('flow_duration', type=int, required=False, location='form')

ai_events_filter.add_argument('attack_type', type=str, required=False, location='form')
ai_events_filter.add_argument('first', type=inputs.datetime_from_iso8601, required=True, location='form')
ai_events_filter.add_argument('last', type=inputs.datetime_from_iso8601, required=True, location='form')

top_by_kind = api.parser()
top_by_kind.add_argument('max_num_res', type=int, required=False, location='args')
top_by_kind.add_argument('kind', type=int, required=True, location='args', 
                     help='0 - src ip, 1 - for dest ip, 2 - src port, 3 - dest port, 4 - protocol')

@api.route('')
class EventList(Resource):
    @token_required
    @api.expect(pagination)
    @api.response(code=200, model=ai_events_response, description='')
    def get(self):
        '''
        Get all ai events
        
        :return: list ai events info
        '''
        args = pagination.parse_args()
        controller = AIEventsController()
        return controller.get(args=args)
    
    @token_required
    @api.expect(ai_events_filter)
    @api.response(code=200, model=ai_events_response, description='')
    def post(self):
        '''
        Filtering ai event info
        ----------------------------
        
        :return: ai event info
        '''
        args = ai_events_filter.parse_args()
        controller = AIEventsController()
        return controller.filter(args=args)
        
@api.route('/count_by_attack')
class CountByAttack(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Count detection by attack
        
        :return:
        '''
        controller = AIEventsController()
        return controller.count_by_attack()
    
@api.route('/get_attacks')
class GetAttacks(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get attack types name in the system
        
        :return:
        '''
        controller = AIEventsController()
        return controller.get_attacks()

@api.route('/get_top_by_kind')
class TopByKind(Resource):
    @api.response(code=200, description='')
    @api.expect(top_by_kind)
    def get(self):
        '''
        Get top ips
        '''
        args = top_by_kind.parse_args()
        controller = AIEventsController()
        return controller.top_by_kind(args)