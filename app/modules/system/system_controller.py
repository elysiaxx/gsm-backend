from utils.message_code import ErrorCode
from utils.response import send_error, send_result
from utils.util import get_cpu_usage, get_disk_usage, get_memory_usage, get_net_ifaddrs, get_net_usage

class SystemController():
    
    def get_cpu_usage(self):
        '''
        Get information of CPUs usage

        :return: Percentage of CPU usage 
        '''
        try:
            cpus_usage, err = get_cpu_usage()
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            return send_result(code=200, data=cpus_usage)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__*())
    
    def get_memory_usage(self):
        '''
        Get information of Memory usage

        :return: Memory usage information
        '''
        try:
            mem_usage, err = get_memory_usage()
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            return send_result(code=200, data=mem_usage)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())

    def get_net_usage(self):
        '''
        Get information of Network band widdth

        :return: Network band width information
        '''
        try:
            net_usage, err = get_net_usage()
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            return send_result(code=200, data=net_usage)
        except Exception as e:
            return send_error(code=ErrorCode)

    def get_disk_usage(self):
        '''
        Get information of Disk usage

        :return: Disk usage information
        '''
        try:
            disk_usage, err = get_disk_usage()
            if err is not None:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)
            return send_result(code=200, data=disk_usage)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def get_if_addrs(self):
        '''
        Get infomation of interfaces in the system
        ----------------------------------
        
        :return: Interfaces information
        '''
        try:
            ifaddrs = get_net_ifaddrs()
            res = {}
            for ifaddr in ifaddrs:
                res[ifaddr] = []
                
                for inf in ifaddrs[ifaddr]:
                    res[ifaddr].append({
                        "family": inf.family,
                        "address": inf.address 
                    })
                    
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())