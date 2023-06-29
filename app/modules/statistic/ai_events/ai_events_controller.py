from app import db
from flask_restx import marshal
from sqlalchemy import func
from datetime import datetime

from app.modules.statistic.ai_events.ai_events import AIEvents
from app.modules.statistic.ai_events.ai_events_dto import AIEventsDto
from app.modules.statistic.ai_events.attack_types.attack_types import AttackTypes

from utils.response import send_error, send_result
from utils.message_code import ErrorCode
from utils.util import ip2int, list_2_dict, protocol_2_int


class AIEventsController():
    
    def get(self, args):
        '''
        Get all ai events
        
        :return: list of ai events info
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = db.session.query(
                AIEvents
                
            ).join(AttackTypes, AttackTypes.id==AIEvents.attack_type)\
            .filter(AttackTypes.id != 1)\
            .with_entities(
                AIEvents.timestamp,
                AIEvents.protocol,
                
                AttackTypes.name,
                AIEvents.src_ip,
                AIEvents.src_port,
                
                AIEvents.dst_ip,
                AIEvents.dst_port,
                AIEvents.flow_duration
                
            ).order_by(AIEvents.timestamp.desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)
            
            items = [
                {
                    "time": time,
                    "protocol": protocol,
                    
                    "attack_type": attack_type,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_duration": flow_duration
                    
                }
                for (time, protocol, attack_type, src_ip, src_port, dst_ip, dst_port, flow_duration) in data.items
            ]
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, AIEventsDto.model_response)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def filter(self, args):
        '''
        filtering ai events
        
        :return: 
        '''
        if not isinstance(args, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your data must be an instance of dictionary')
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            ais = db.session.query(
                AIEvents
            ).join(AttackTypes, AttackTypes.id==AIEvents.attack_type)\
            .with_entities(
                AIEvents.timestamp,
                AIEvents.protocol,
                
                AttackTypes.name,
                AIEvents.src_ip,
                AIEvents.src_port,
                
                AIEvents.dst_ip,
                AIEvents.dst_port,
                AIEvents.flow_duration
                
            ).filter(AIEvents.attack_type != 1)\
            .filter(
                AIEvents.timestamp>=args.first,
                AIEvents.timestamp<=args.last
            ).order_by(AIEvents.timestamp.desc())

            if args.protocol:
                ais = ais.filter(AIEvents.protocol==protocol_2_int(args.protocol.strip()))
            if args.attack_type:
                ais = ais.filter(AIEvents.attack_type==args.attack_type)
                
            if args.src_ip:
                ais = ais.filter(AIEvents.src_ip==ip2int(args.src_ip.strip()))
            if args.src_port:
                ais = ais.filter(AIEvents.src_port==args.src_port)
                
            if args.dst_ip:
                ais = ais.filter(AIEvents.dst_ip==ip2int(args.dst_ip.strip()))
            if args.dst_port:
                ais = ais.filter(AIEvents.dst_port==args.dst_port)
                
            data = ais.paginate(page=page, per_page=pageSize, error_out=False)

            items = [
                {
                    "time": time,
                    "protocol": protocol,
                    
                    "attack_type": attack_type,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flow_duration": flow_duration
                    
                }
                for (time, protocol, attack_type, src_ip, src_port, dst_ip, dst_port, flow_duration) in data.items
            ]
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, AIEventsDto.model_response)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def count_by_attack(self):
        '''
        Count detection by attack
        
        :return:
        '''
        try:
            data = db.session.query(
                AIEvents
            ).join(AttackTypes, AttackTypes.id==AIEvents.attack_type)\
            .filter(AIEvents.attack_type != 1)\
            .with_entities(
                
                AttackTypes.name,
                func.count(AIEvents.flow_id)
            ).filter(AttackTypes.id != 1)\
            .group_by(AttackTypes.name).all()
            
            res = list_2_dict(
                ["name", "count"],
                data
            )
            
            return send_result(code=200, data=marshal(res, AIEventsDto.count_by_attack))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def get_attacks(self):
        '''
        Get all attacks name in the system
        
        :return: list attack name
        '''
        try:
            data = AttackTypes.query.filter(AttackTypes.id != 1).all()
            return send_result(code=200, data=marshal(data, AIEventsDto.attacks))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
        
    def top_by_kind(self, args):
        '''
        Get number of event of source ips in top
        
        :params: 
            kind: 0 - src ip
                  1 - dst ip
                  2 - src port
                  3 - dst port
                  4 - protocol
            max_num_res: maximum number of result, default equal 15
        :return:
        '''
        if args.kind is None:
            return send_error(code=4000, message="Your request must have kind param")
        try:
            max_num_res = args.max_num_res if args.max_num_res else 15
            data = db.session.query(
                AIEvents
            )
            
            if args.kind == 0:
                data = data.with_entities(
                    AIEvents.src_ip,
                    func.count(AIEvents.src_ip)
                    
                ).group_by(
                    AIEvents.src_ip
                ).order_by(
                    func.count(AIEvents.src_ip).desc()
                    
                ).paginate(page=1, per_page=max_num_res, error_out=False)
                items = marshal([{"ip": x, "amount": y} for x, y in data.items], AIEventsDto.model_top_by_ip)
                
            if args.kind == 1:
                data = data.with_entities(
                    AIEvents.dst_ip,
                    func.count(AIEvents.dst_ip)
                    
                ).group_by(
                    AIEvents.dst_ip
                ).order_by(
                    func.count(AIEvents.dst_ip).desc()
                    
                ).paginate(page=1, per_page=max_num_res, error_out=False)
                items = marshal([{"ip": x, "amount": y} for x, y in data.items], AIEventsDto.model_top_by_ip)
                
            if args.kind == 2: 
                data = data.with_entities(
                    AIEvents.src_port,
                    func.count(AIEvents.src_port)
                    
                ).group_by(
                    AIEvents.src_port
                ).order_by(
                    func.count(AIEvents.src_port).desc()
                    
                ).paginate(page=1, per_page=max_num_res, error_out=False)
                items = marshal([{"port": x, "amount": y} for x, y in data.items], AIEventsDto.model_top_by_port)
                
            if args.kind == 3:
                data = data.with_entities(
                    AIEvents.dst_port,
                    func.count(AIEvents.dst_port)
                    
                ).group_by(
                    AIEvents.dst_port
                ).order_by(
                    func.count(AIEvents.dst_port).desc()
                    
                ).paginate(page=1, per_page=max_num_res, error_out=False)
                items = marshal([{"port": x, "amount": y} for x, y in data.items], AIEventsDto.model_top_by_port)

            if args.kind == 4:
                data = data.with_entities(
                    AIEvents.protocol,
                    func.count(AIEvents.protocol)
                    
                ).group_by(
                    AIEvents.protocol
                ).order_by(
                    func.count(AIEvents.protocol).desc()
                    
                ).paginate(page=1, per_page=max_num_res, error_out=False)
                items = marshal([{"protocol": x, "amount": y} for x, y in data.items], AIEventsDto.model_top_by_proto)
                
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(message=e.__str__())