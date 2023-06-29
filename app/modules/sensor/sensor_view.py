from flask import request
from flask_restx import Resource

from app.modules.sensor.sensor_controller import SensorController
from app.modules.sensor.sensor_dto import SensorDto
from app.modules.auth.decorator import token_required, admin_token_required

api = SensorDto.api

sensor_request = SensorDto.model_request 
sensor_response = SensorDto.model_response

sensor_list = api.parser()
sensor_list.add_argument('page', type=int, location='args')
sensor_list.add_argument('pageSize', type=int, location='args')

sensor_info_request = SensorDto.model_sensor_request
sensor_info_response = SensorDto.model_sensor_response
sensor_update_request = SensorDto.model_sensor_update

sensor_action_request = api.parser()
sensor_action_request.add_argument('action', type=str, required=True, location='args')


@api.route('/statistic')
class StatisticSensor(Resource):
    # @token_required
    @api.response(code=200,model=sensor_response,description='Model for sensors response.')
    @api.expect(sensor_list)
    def get(self):
        '''
        Returns all sensors in the system.
        -------------------------

        :return List of sensors.
        '''
        args = sensor_list.parse_args()
        controller = SensorController()
        return controller.get_statistic_sensors(args.page, args.pageSize)


@api.route('/count')
class SensorCount(Resource):
    # @token_required
    @api.response(code=200,description='Model for Sensor Counter response.')
    def get(self):
        '''
        Returns number of sensors in the system
        --------------------------

        :return Number of sensors.
        '''
        controller = SensorController()
        return controller.num_of_sensors()

    
@api.route('')
class SensorList(Resource):
    @api.response(code=200, model=sensor_info_response, description='')
    def get(self):
        '''
        Get sensors info
        -------------------------
        
        :return: Sensor information
        '''
        controller = SensorController()
        return controller.get_sensors_info()
        
        
    @admin_token_required
    @api.response(code=200, model=sensor_info_response, description='')
    @api.expect(sensor_info_request)
    def post(self):
        '''
        Create new sensor
        ---------------------
        
        :return: sensor info object
        '''
        data = api.payload
        controller = SensorController()
        return controller.create_sensor(data=data, req=request)
    
@api.route('/<int:id>')
class Sensor(Resource):
    # @token_required
    @api.response(code=200, description='')
    def get(self, id):
        '''
        To turn on/off sensor and get back stats info.
        
        :return: Stats info
        '''
        controller = SensorController()
        return controller.get_sensor_info(object_id=id)
    
    @token_required
    @api.response(code=200, model=sensor_info_response, description='')
    @api.expect(sensor_update_request)
    def put(self, id):
        '''
        Update an existed sensor
        --------------------

        :return: The sensor information data after updated.
        '''
        data = api.payload
        controller = SensorController()
        return controller.update_sensor_info(object_id=id, data=data, req=request)
    
    @admin_token_required
    def delete(self, id):
        '''
        Delete the sensor with the Name `name`
        -----------------

        :param name: The Name of the sensor to be deleted.

        :return: True if user delete successfully and False vice versa.
        '''
        controller = SensorController()
        return controller.delete_sensor_info(object_id=id)
    

@api.route('/<int:id>/action')
class SensorAction(Resource):
    @admin_token_required
    @api.expect(sensor_action_request)
    @api.response(code=200, description='')
    def get(self, id):
        '''
        To turn on/off sensor and get back stats info.
        
        :return: Stats info
        '''
        args = sensor_action_request.parse_args()
        controller = SensorController()
        return controller.action(object_id=id, action=args['action'])
