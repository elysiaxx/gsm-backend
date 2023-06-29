
from flask_restx import marshal
from datetime import datetime, timedelta

from app.modules.monitor.monitor_dto import MonitorDto
from app.modules.monitor.network_packets import NetworkPacket

from utils.response import send_error, send_result
from utils.message_code import ErrorCode
from utils.util import datetime_2_int, fill_data_monitor, reparse_proto


class MonitorController():
    
    def get(self, args):
        '''
        Get network packets in the system
        
        :return: list network packet
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            data = NetworkPacket.objects.order_by('-timestamp')\
            .paginate(page=page, per_page=pageSize)
            items = marshal(data.items, MonitorDto.model_response)
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def filter(self, args):
        '''
        Filter network packets
        
        :return:
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            fdict = dict()
            if args.src_ip:
                fdict['src_ip'] = args.src_ip.strip()
            if args.dst_ip:
                fdict['dst_ip'] = args.dst_ip.strip()
                
            if args.src_port:
                fdict['src_port'] = args.src_port.strip()
            if args.dst_port:
                fdict['dst_port'] = args.dst_port.strip()
            
            data = []
            if args.first and args.last:
                data = NetworkPacket.objects(
                    timestamp__gt=args.first.strftime("%Y/%m/%d %H:%M:%S"),
                    timestamp__lte=args.last.strftime("%Y/%m/%d %H:%M:%S")
                ).order_by('-timestamp')
            else:
                data = NetworkPacket.objects().order_by('-timestamp')
            
            data = data.filter(
                **fdict
            ).paginate(page=page, per_page=pageSize, error_out=False)
            
            items = marshal(data.items, MonitorDto.model_response)
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def count_packets_protocol(self):
        '''
        Get number packets by protocol
        
        :return: number packets each protocol
        '''
        try:
            pipeline = [
                {"$addFields": {"convertedProtocol":"$protocol"}}, 
                {"$group": {"_id": "$convertedProtocol", "count": { "$sum": 1}}}, 
                {"$project": {"_id": 0, "protocol": "$_id", "count": 1}}
            ]
            
            data = list(NetworkPacket.objects().aggregate(pipeline))
            res = reparse_proto(data)
            return send_result(code=200, data=marshal(res, MonitorDto.packets_protocol))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def top_n_ips(self, args):
        '''
        Get top ips
        
        :return:
        '''
        if not args.kind:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="Your request doesn't have kind")
        if args.kind not in ['src_ip', 'dst_ip']:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message='Kind query value must be in ["src_ip", "dst_ip"]')
        
        try:
            limit = args.limit if args.limit else 10
            pipeline = [
                {"$unwind": "${}".format(args.kind)},
                
                {"$group": {"_id": "${}".format(args.kind), "count": { "$sum": 1}}}, 
                {"$project": {"_id": 0, "{}".format(args.kind): "$_id", "count": 1}},
                {"$sort": {"count": -1}},
                {"$limit": limit }
            ]
            
            data = list(NetworkPacket.objects().aggregate(pipeline))
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def duration_of_flow(self):
        '''
        Get duration of flow
        
        :return:
        '''
        try:
            current_time = datetime.now()
            current_time = current_time - timedelta(minutes=5)
            pass_5_minutes = current_time - timedelta(minutes=5)

            data = NetworkPacket.objects(
                timestamp__gte=pass_5_minutes.strftime("%Y/%m/%d %H:%M:%S"),
                timestamp__lt=current_time.strftime("%Y/%m/%d %H:%M:%S")
            )
            
            res = [x for x in data]
            data = marshal(res, MonitorDto.flow_duration)
            data = fill_data_monitor(
                data,
                
                round(pass_5_minutes.timestamp()),
                round(current_time.timestamp()),
                ["flow_duration"]
            )
            
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def number_packets_per_second(self):
        '''
        Get Number of packets per second
        
        :return: 
        '''
        try:
            current_time = datetime.now()
            current_time = current_time - timedelta(minutes=5)
            pass_5_minutes = current_time - timedelta(minutes=5)
            
            data = NetworkPacket.objects(
                timestamp__gte=pass_5_minutes.strftime("%Y/%m/%d %H:%M:%S"),
                timestamp__lt=current_time.strftime("%Y/%m/%d %H:%M:%S")
            )
            
            res = [x for x in data]
            data = marshal(res, MonitorDto.packets_per_second)
            data = fill_data_monitor(
                data,
                
                round(pass_5_minutes.timestamp()),
                round(current_time.timestamp()),
                ["fwd_pkts_s", "bwd_pkts_s"]
            )
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def download_upload_ratio(self):
        '''
        Get download and upload ratio
        
        :return: 
        '''
        try:
            current_time = datetime.now()
            current_time = current_time - timedelta(minutes=5)
            pass_5_minutes = current_time - timedelta(minutes=5)

            data = NetworkPacket.objects(
                timestamp__gte=pass_5_minutes.strftime("%Y/%m/%d %H:%M:%S"),
                timestamp__lt=current_time.strftime("%Y/%m/%d %H:%M:%S")
            )
            
            res = [x for x in data]
            data = marshal(res, MonitorDto.download_upload_ratio)
            data = fill_data_monitor(
                data,
                
                round(pass_5_minutes.timestamp()),
                round(current_time.timestamp()),
                ["down_up_ratio"]
            )
            
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def flow_pkts_byts(self):
        '''
        Get flow packets and flow bytes per second
        
        :return: 
        '''
        try:
            current_time = datetime.now()
            current_time = current_time - timedelta(minutes=5)
            pass_5_minutes = current_time - timedelta(minutes=5)
            
            data = NetworkPacket.objects(
                timestamp__gte=pass_5_minutes.strftime("%Y/%m/%d %H:%M:%S"),
                timestamp__lt=current_time.strftime("%Y/%m/%d %H:%M:%S")
            )
            
            res = [x for x in data]
            data = marshal(res, MonitorDto.flow_pkts_byts)
            data = fill_data_monitor(
                data,
                
                round(pass_5_minutes.timestamp()),
                round(current_time.timestamp()),
                ["flow_pkts_s", "flow_byts_s"]
            )
            
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def total_packets(self):
        '''
        Get number of packets per second
        
        :return: 
        '''
        try:
            current_time = datetime.now()
            current_time = current_time - timedelta(minutes=5)
            pass_5_minutes = current_time - timedelta(minutes=5)
            
            data = NetworkPacket.objects(
                timestamp__gte=pass_5_minutes.strftime("%Y/%m/%d %H:%M:%S"),
                timestamp__lt=current_time.strftime("%Y/%m/%d %H:%M:%S")
            )
            
            res = [x for x in data]
            data = marshal(res, MonitorDto.total_packets)
            data = fill_data_monitor(
                data,
                
                round(pass_5_minutes.timestamp()),
                round(current_time.timestamp()),
                ["tot_fwd_pkts", "tot_bwd_pkts"]
            )
            
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def total_size_packet(self):
        '''
        Get Number of packets per second
        
        :return: 
        '''
        try:
            current_time = datetime.now()
            current_time = current_time - timedelta(minutes=5)
            pass_5_minutes = current_time - timedelta(minutes=5)
            
            data = NetworkPacket.objects(
                timestamp__gte=pass_5_minutes.strftime("%Y/%m/%d %H:%M:%S"),
                timestamp__lt=current_time.strftime("%Y/%m/%d %H:%M:%S")
            )
            
            res = [x for x in data]
            data = marshal(res, MonitorDto.total_size_packet)
            data = fill_data_monitor(
                data,
                
                round(pass_5_minutes.timestamp()),
                round(current_time.timestamp()),
                ["totlen_fwd_pkts", "totlen_bwd_pkts"]
            )
            
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    

    