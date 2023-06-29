from datetime import datetime
from ipaddress import IPv4Address
import ipaddress
import socket

from flask import request
from flask_restx.fields import Date
from flask_restx.marshalling import marshal
import sqlalchemy


from sqlalchemy.orm import joinedload
from sqlalchemy import func
from sqlalchemy.sql.expression import distinct

from app import db
from app.modules.auth.auth_controller import AuthController
from app.modules.statistic.report_events.report_events import ReportEvents

from app.modules.sensor.sensor import Sensor
from app.modules.sensor.sensor_dto import SensorDto
from app.modules.sensor.sensor_info import SensorInfo

from utils.response import send_error,send_result
from utils.util import change_home_net,check_barnyard_config, check_home_net, check_snort_config, create_dir, create_dir_sensor, datetime_2_int, get_net_ifaddrs, list_2_dict, make_barnyard_config, make_barnyard_waldo, make_snort_config
from utils.util import start_network_service, stop_network_service
from utils.message_code import ErrorCode


class SensorController():
    
    def get(self):
        '''
        Get all sensors in the system.
        :return: List of sensors.
        '''
        try:
            sensors = Sensor.query.all()
            return send_result(data=marshal(sensors,SensorDto.model_response))
        except Exception as e:
            print(e.__str__())
            return send_error('Could not load error, please try again later')

    def get_by_id(self,object_id):
        '''
        Get sensor by sid

        :param object_id: The sensor id
        
        :return: The info of sensor
        '''
        try:
            sensor = Sensor.query.filter_by(sid=object_id).first()
            return send_result(data=marshal(sensor,SensorDto.model_response))
        except Exception as e:
            print(e.__str__())
            return send_error('Could not load error, please try again later')

    def num_of_sensors(self):
        '''
        Get number of sensors in the system
        
        :return: The number of sensors
        '''
        try:
            num_sensors = db.session.query(Sensor).count()
            return send_result(data=num_sensors)
        except Exception as e:
            print(e.__str__())
            return send_error('Could not load error, please try again later')

    def get_statistic_sensors(self, page=1, pageSize=50):
        '''
        Statistic info of sensor

        :param sid: Sensor ID

        :return: Info ralated to a sensor 
        '''
        try:
            statistic_sensors = db.session.query(
                ReportEvents, Sensor
            ).filter(Sensor.sid==ReportEvents.sid)\
            .with_entities(
                ReportEvents.sid,
                Sensor.hostname,
                Sensor.interface,

                func.count(ReportEvents.cid),
                func.count(distinct(ReportEvents.signature)),
                func.count(distinct(ReportEvents.ip_src)),

                func.count(distinct(ReportEvents.ip_dst)),
                func.min(ReportEvents.timestamp),
                func.max(ReportEvents.timestamp),
            )\
            .group_by(ReportEvents.sid)\
            .paginate(page, pageSize, error_out=False).items
            
            data = list_2_dict(
                ["sensor", "hostname", "interface", "total_events", "unique_events", "src_addr", "dst_addr", "first", "last"],
                statistic_sensors
                )
            return send_result(code=200, data=marshal(data,SensorDto.model_statistic_sensor))
        except Exception as e:
            return send_error(message=e.__str__())

    def get_statistic_sensor(self, sid):
        '''
        Statistic info of sensor

        :param sid: Sensor ID

        :return: Info ralated to a sensor 
        '''
        try:
            statistic_sensor = db.session.query(
                ReportEvents, Sensor
            ).filter( ReportEvents.sid == sid).filter(Sensor.sid==ReportEvents.sid)\
            .with_entities(
                ReportEvents.sid,
                Sensor.hostname,
                Sensor.interface,

                func.count(ReportEvents.cid),
                func.count(distinct(ReportEvents.signature)),
                func.count(distinct(ReportEvents.ip_src)),

                func.count(distinct(ReportEvents.ip_dst)),
                func.min(ReportEvents.timestamp),
                func.max(ReportEvents.timestamp),
            )\
            .group_by(ReportEvents.sid).all()

            data = list_2_dict(
                ["sensor", "hostname", "interface", "total_events", "unique_events", "src_addr", "dst_addr", "first", "last"],
                statistic_sensor
                )
            return send_result(code=200, data=marshal(data,SensorDto.model_statistic_sensor))
        except Exception as e:
            return send_error(message=e.__str__())
        
    def create_sensor(self, data, req):
        '''
        Create sensor

        :param data: sensor info object data

        :return: sensor info object data 
        '''
        if 'name' not in data \
            or 'description' not in data \
            or 'interface' not in data \
            or 'address' not in data:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Params {name, description, interface, address} are required')
        try:
            if isinstance(ipaddress.ip_address(data['address']), IPv4Address) is False:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Address is incorrect format of IPv4 address')
            if data['interface'] not in get_net_ifaddrs():
                return send_error(code=ErrorCode.BAD_REQUEST, message='Interface isn\'t exist in the system')
            
            ss = SensorInfo.query.filter_by(interface=data['interface']).first()
            if ss:
                return send_error(code=ErrorCode.BAD_REQUEST, message='interface alread exist')
            
            if 'home_net' in data:
                if check_home_net(data['home_net']) is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message='home_net is incorrect format')
                
            
            sensorIF = self._parse_sensor_info(data, None)
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(message=message)
            
            sensorIF.created_by = user.email
            sensorIF.updated_by = user.email
            
            tmpTime = datetime.now()
            
            sensorIF.log_dir = '/var/log/snort/{0}.{1}'.format(sensorIF.name, str(datetime_2_int(tmpTime)))
            sensorIF.config_dir = '/etc/snort/{0}.{1}'.format(sensorIF.name, str(datetime_2_int(tmpTime)))
            
            sensorIF.created_at = datetime.now()
            sensorIF.updated_at = datetime.now()
            
            ok, err = create_dir_sensor(sensorIF.log_dir)
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            ok, err = create_dir_sensor(sensorIF.config_dir)
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            ok, err = make_barnyard_waldo('{0}/barnyard2.waldo'.format(sensorIF.log_dir))
            
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)

            ok, err = make_barnyard_config('{0}/'.format(sensorIF.config_dir), socket.gethostname(), sensorIF.interface)
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)

            ok, err = make_snort_config('{0}/'.format(sensorIF.config_dir), '{0}/'.format(sensorIF.log_dir), sensorIF.home_net)
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)

            ok, err = change_home_net(data['home_net'], sensorIF.config_dir)
            if ok is False:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message='Change home_net fail')
            # ok, err = check_snort_config('{0}/snort.conf'.format(sensorIF.config_dir), sensorIF.interface)
            # if err is not None:
            #     return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            
            sensorIF.sensor_status = "Stopped"
            db.session.add(sensorIF)
            db.session.commit()
            
            return send_result(code=200, data=marshal(sensorIF, SensorDto.model_sensor_response))
        except Exception as e:
            if isinstance(e, ValueError) is True:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Address is incorrect format')
            if isinstance(e, sqlalchemy.exc.IntegrityError) is True:
                return send_error(code=ErrorCode.BAD_REQUEST, message=e.__str__())
                
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
                
    def get_sensors_info(self):
        '''
        Get sensors information
        
        :return: Sensors information
        '''
        try:
            sensors_info = SensorInfo.query.all()
            return send_result(data=marshal(sensors_info, SensorDto.model_sensor_response), message='Success')
        except Exception as e:
            return send_error(ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def get_sensor_info(self, object_id):
        '''
        Get sensor information by ID
        
        :param object_id: sensor ID
        
        :return: Sensor information
        '''
        if object_id is None:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Sensor ID must not be null')
        try:
            sensorIF = SensorInfo.query.filter_by(id=object_id).first()
            if sensorIF is None:
                return send_error(code=ErrorCode.NOT_FOUND, message='Sensor information not found')
            return send_result(code=200, data=marshal(sensorIF, SensorDto.model_sensor_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def update_sensor_info(self, object_id, data, req):
        '''
        Update sensor info.

        :param object_id: name of sensor

        :param data: data to update

        :return:
        '''
        if not isinstance(data, dict):
            return send_error(message='You must pass dictionary-like data.')
        try:
            if 'address' in data:
                if isinstance(ipaddress.ip_address(data['address']), IPv4Address) is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message='Address is incorrect format of IPv4 address')
            if 'interface' in data:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Can\'t modify interface of sensor')
            
            sensorIF = SensorInfo.query.filter_by(id=object_id).first()
            if sensorIF is None:
                return send_error(code=ErrorCode.BAD_REQUEST, message='Sensor not found')

            if sensorIF.sensor_status != 'Stopped':
                return send_error(code=ErrorCode.FORBIDDEN, message="You must stop sensor before update")
            
            if 'home_net' in data:
                if check_home_net(data['home_net']) is False:
                    return send_error(code=ErrorCode.BAD_REQUEST, message='home_net is incorrect format')
                ok, err = change_home_net(data['home_net'], sensorIF.config_dir)
                if ok is False:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message='Change home_net fail')
            sensor_info = self._parse_sensor_info(data=data, sensorIF=sensorIF)
            
            user, message = AuthController.get_logged_user(req=req)
            if user is None:
                return send_error(message=message)
            
            sensorIF.updated_by = user.email
            sensor_info.updated_at = datetime.now()
            db.session.commit()
            
            return send_result(message='Update successfully', data=marshal(sensor_info, SensorDto.model_sensor_response))
        except sqlalchemy.exc.IntegrityError as e:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Sensor name must be unique')
        except ValueError as e:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Address is incorrect format')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
            
    def delete_sensor_info(self, object_id):
        '''
        Delete sensor info.

        :param object_id: Sensor

        :return:
        '''
        try:
            sensor_info = SensorInfo.query.filter_by(id=object_id).first()
            if not sensor_info:
                return send_error(code=ErrorCode.NOT_FOUND, message='Sensor not found')
            else:
                if sensor_info.sensor_status != 'Stopped':
                    return send_error(ErrorCode.BAD_REQUEST, message='Sensor must be turned off before deleting')
                db.session.delete(sensor_info)
                db.session.commit()
                return send_result(code=200, message='Sensor info was deleted successfully')
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message='Could not delete sensor')
        
    def action(self, object_id, action):
        '''
        To turn on/off network service in the system
        
        :param action: Start/Stop 
        
        :return: True if success and vice versa
        '''
        if action != 'Start' and action != 'Stop':
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message='Action must be "Start" or "Stop"') 
        try:
            sensorIF = SensorInfo.query.filter_by(id=object_id).first()
            if sensorIF is None:
                return send_error(code=ErrorCode.NotFound, message='Sensor not found')
            
            if action == 'Start':
                if sensorIF.sensor_status == 'Running':
                    return send_error(code=ErrorCode.FORBIDDEN, message='Sensor already running')
                barnyard2 = True if sensorIF.barnyard2_pid is None else False
                ok, data, err = start_network_service(sensorIF.config_dir, sensorIF.log_dir, sensorIF.interface, barnyard2=barnyard2)
                if ok is False:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
                
                if data is not None and data != []:
                    sensorIF.snort_pid = data[0]
                    if len(data) == 2:
                        sensorIF.barnyard2_pid = data[1]
                    sensorIF.sensor_status = "Running"
                    db.session.commit()
                return send_result(code=200, message='Success')
            
            if action == 'Stop':
                if sensorIF.sensor_status == 'Stopped':
                    return send_error(code=ErrorCode.FORBIDDEN, message='Sensor already turning off')
                ok, err = stop_network_service(sensorIF.config_dir, sensorIF.log_dir, sensorIF.snort_pid, sensorIF.barnyard2_pid)
                if ok is False:
                    return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
                sensorIF.snort_pid = None
                sensorIF.barnyard2_pid = None
                sensorIF.sensor_status = "Stopped"
                db.session.commit()
                return send_result(code=200, message='Success')
            
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
                            
        
    def _parse_sensor_info(self, data, sensorIF=None):
        if sensorIF is None:
            sensorIF = SensorInfo()

        if 'interface' in data:
            sensorIF.interface = data['interface']
        if 'address' in data:
            sensorIF.address = data['address']
        
        if 'description' in data:
            sensorIF.description = data['description']
        if 'name' in data:
            sensorIF.name = data['name']
        
        if 'sensor_status' in data:
            sensorIF.sensor_status = data['sensor_status']
        if 'home_net' in data:
            sensorIF.home_net = data['home_net']

        return sensorIF
            
  