from flask_restx import Resource, inputs

from app.modules.monitor.monitor_dto import MonitorDto
from app.modules.monitor.monitor_controller import MonitorController


api = MonitorDto.api

top_n_ips = api.parser()
top_n_ips.add_argument('kind', type=str, required=True, location='args')
top_n_ips.add_argument('limit', type=int, required=False, location='args')

pagination = api.parser()
pagination.add_argument('page', type=int, required=False, location='args')
pagination.add_argument('pageSize', type=int, required=False, location='args')

filter = pagination.copy()
filter.add_argument('src_ip', type=str, required=False, location='form')
filter.add_argument('dst_ip', type=str, required=False, location='form')
filter.add_argument('src_port', type=str, required=False, location='form')
filter.add_argument('dst_port', type=str, required=False, location='form')
filter.add_argument('first', type=inputs.datetime_from_iso8601, required=False, location='form')
filter.add_argument('last', type=inputs.datetime_from_iso8601, required=False, location='form')


@api.route('')
class Monitor(Resource):
    @api.expect(pagination)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get network packets in the system
        
        :return: list network packet
        '''
        args = pagination.parse_args()
        controller = MonitorController()
        return controller.get(args=args)

@api.route('/filter')
class Filter(Resource):
    @api.expect(filter)
    @api.response(code=200, description='')
    def post(self):
        '''
        Filter network packets
        
        :return:
        '''
        args = filter.parse_args()
        controller = MonitorController()
        return controller.filter(args=args)

@api.route('/count_packets_of_protocol')
class PacketProtocol(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get number packets by protocol
        
        :return: number packets each protocol
        '''
        controller = MonitorController()
        return controller.count_packets_protocol()
    
@api.route('/top_n_ips')
class PacketIps(Resource):
    @api.expect(top_n_ips)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get top packets by ip
        
        :return:
        '''
        args = top_n_ips.parse_args()
        controller = MonitorController()
        return controller.top_n_ips(args=args)
        

@api.route('/flow_duration')
class FlowDuration(Resource):

    @api.response(code=200, description='')
    def get(self):
        '''
        Get flow duration
        
        :return:
        '''
        controller = MonitorController()
        return controller.duration_of_flow()
    

@api.route('/number_packets_per_second')
class NumPacketsPerSecond(Resource):
    
    @api.response(code=200, description='')
    def get(self):
        '''
        Get Number of packets per second
        
        :return: 
        '''
        controller = MonitorController()
        return controller.number_packets_per_second()
    

@api.route('/download_upload_ratio')
class DownUploadRatio(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get download and upload ratio
        
        :return: 
        '''
        controller = MonitorController()
        return controller.download_upload_ratio()


@api.route('/flow_pkts_byts')
class FlowPktsBkts(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get flow packets and flow bytes per second
        
        :return: 
        '''
        controller = MonitorController()
        return controller.flow_pkts_byts()


@api.route('/total_packets')
class TotalPackets(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get Number of packets per second
        
        :return: 
        '''
        controller = MonitorController()
        return controller.total_packets()


@api.route('/total_size_packet')
class TotalSizePacket(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get Number of packets per second
        
        :return: 
        '''
        controller = MonitorController()
        return controller.total_size_packet()
