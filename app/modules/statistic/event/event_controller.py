from flask_restx.marshalling import marshal
from sqlalchemy.sql.functions import func

from app import db
from app.modules.statistic.event.event import Event
from app.modules.statistic.event.event_dto import EventDto
from utils.response import send_error, send_result


class EventController():

    def get(self):
        '''
        Get all events in the system
        :return: List of events.
        '''
        try:
            events = Event.query.all()
            return send_result(data=marshal(events,EventDto.model_response))
        except Exception as e:
            print(e.__str__())
            return send_error(e.__str__())

    def get_by_sid_cid(self,object_sid,object_cid):
        '''
        Get event by sensor ID

        :param sid: sensor ID
        :param cid: count ID
        :return: The information of Event
        '''
        try:
            event = Event.query.filter_by(sid=object_sid,cid=object_cid).first()
            return send_result(data=marshal(event,EventDto.model_response))
        except Exception as e:
            return send_error(e.__str__())

    def num_events(self):
        '''
        Get number of events in the system

        :return: Number of events.
        '''
        try:
            num_events = Event.query.count()
            return send_result(data=num_events)
        except Exception as e:
            print(e.__str__())
            return send_error(e.__str__())

    def num_events_of_sensor(self,object_id):
        '''
        Get number of event of a sensor in the system.

        :return: The number of event of a sensor.
        '''
        try:
            num_event_of_sensor = Event.query.filter_by(sid=object_id).count()
            return send_result(data=num_event_of_sensor)
        except Exception as e:
            return send_error(e.__str__())
