from flask_restx import Resource

from app.modules.statistic.event.event_controller import EventController
from app.modules.statistic.event.event_dto import EventDto
from app.modules.auth.decorator import token_required, admin_token_required

api = EventDto.api

event_request = EventDto.model_request 
event_response = EventDto.model_response

check_parser = api.parser()


@api.route('')
class EventList(Resource):
    # @token_required
    @api.response(code=200,model=event_response,description='Model for event response.')
    def get(self):
        '''
        Returns all events in the system
        ----------------------
        
        :return List of events.
        '''
        controller = EventController()
        return controller.get()


@api.route('/count')
class EventsCount(Resource):
    # @token_required
    @api.response(code=200,description='')
    def get(self):
        '''
        Return number of event in the system
        --------------------
        :return Num of events.
        '''
        controller = EventController()
        return controller.num_events()


@api.route('/<int:sid>/<int:cid>')
class Event(Resource):
    # @token_required
    @api.response(code=200,description='')
    def get(self,sid,cid):
        '''
        Returns number of event of sensor by SID.

        :param object_id

        :return Num of event.
        '''
        controller = EventController()
        return controller.get_by_sid_cid(sid,cid)