from flask_restx import Resource
from app.modules.system.system_controller import SystemController

from app.modules.system.system_dto import SystemDto

api = SystemDto.api


@api.route('/cpu')
class CPUsUsage(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get information about CPU usage per second
        ----------------------------------

        :return: Percentage of CPU usage per second
        '''
        controller = SystemController()
        return controller.get_cpu_usage()

@api.route('/mem')
class MemUsage(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get information about Memory usage in the system
        ----------------------------------

        :return: Memory usage information
        '''
        controller = SystemController()
        return controller.get_memory_usage()

@api.route('/disk')
class DiskUsage(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get information about Disk usage in the system
        --------------------------------------

        :return: Disk usage information
        '''
        controller = SystemController()
        return controller.get_disk_usage()

@api.route('/net')
class NetUsage(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get information about Network usage in the system
        --------------------------------------

        :return: Network usage information
        '''
        controller = SystemController()
        return controller.get_net_usage()

@api.route('/if_addrs')
class IfAddrs(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get infomation of interfaces in the system
        ----------------------------------
        
        :return: Interfaces information
        '''
        controller = SystemController()
        return controller.get_if_addrs()