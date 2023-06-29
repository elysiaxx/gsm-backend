from flask_restx import marshal
from sqlalchemy import func, desc
from sqlalchemy.sql.expression import distinct

from app import db
from app.modules.sensor.sensor_info import SensorInfo
from app.modules.statistic.ai_events.ai_events import AIEvents
from app.modules.statistic.ai_events.attack_types.attack_types import AttackTypes
from app.modules.statistic.country.country import Country

from app.modules.statistic.report_events.report_events_dto import ReportEventsDto
from app.modules.statistic.report_events.report_events import ReportEvents

from app.modules.sensor.sensor import Sensor
from app.modules.statistic.sig_class.sig_class import SigClass
from app.modules.statistic.signature.signature import Signature
from utils.countries import country_al2_al3, country_al3_al2

from utils.response import send_error, send_result
from utils.message_code import ErrorCode
from utils.util import convert_ip_2_int, convert_proto_type, ip2int, list_2_dict, priority_str_int, protocol_2_int


class ReportEventsController():
    '''
    '''
    def get(self, args):
        '''
        Get all Report Events in the system

        :return: The info of all Report Events.
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = db.session.query(
              ReportEvents, Country.code
            ).outerjoin(Country, ReportEvents.id_country == Country.id)\
            . with_entities(
                ReportEvents.sid,
                ReportEvents.cid,
                ReportEvents.signature,
                ReportEvents.sig_name,
                ReportEvents.sig_class_id,

                ReportEvents.timestamp,
                ReportEvents.ip_src,
                ReportEvents.ip_dst,
                ReportEvents.ip_proto,
                
                ReportEvents.layer4_sport,
                ReportEvents.layer4_dport,
                ReportEvents.cnc_server,
                ReportEvents.security_level,
                ReportEvents.sig_priority,
                Country.code
            )\
            .paginate(page, pageSize, error_out=False)
            items = list_2_dict(
                ["sid", "cid", "signature" ,"sig_name",
                 "sig_class_id", "sig_priority" "timestamp",
                 "ip_src", "ip_dst", "ip_proto",
                 "layer4_sport", "layer4_dport",
                 "cnc_server", "security_level",
                 "id_country", "country"
                ],
                data.items,
            )
            res = {
                "page": data.page,
                "numer_in_page": len(data.items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_response)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def get_statistic_alerts(self, args):
        '''
        Statistic alerts in the system

        :return: Info of alerts
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = ReportEvents.query.order_by(
                ReportEvents.timestamp.desc()
            ).with_entities(
                ReportEvents.sid,
                ReportEvents.cid,
                ReportEvents.sig_name,

                ReportEvents.timestamp,
                ReportEvents.ip_src,
                ReportEvents.ip_dst,
                ReportEvents.ip_proto
            ).paginate(page, pageSize, error_out=False)

            items = list_2_dict(
                ["sid", "cid", "signature_name", "timestamp", "src_addr", "dst_addr", "layer4_protocol"],
                data.items
            )
            
            res = {
                "page": data.page,
                "numer_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_statistic_alerts)
            }
            
            return send_result(code=200,data=res)
        except Exception as e:
            return send_error(message=e.__str__())

    def get_total_alerts(self):
        '''
        Get total alerts in the system

        :return: number of alerts.    
        '''
        try:
            num_alerts = ReportEvents.query.count()
            return send_result(code=200, data=num_alerts)
        except Exception as e:
            return send_error(message=e.__str__())
    
    def get_last_alerts(self, n):
        '''
        Get n last alerts in the system

        :return: The info of n last alerts.
        '''
        try:
            n = 15 if not n else n
            ai = db.session.query(
                AIEvents.attack_type.label('sig_name'),
                AIEvents.src_ip.label('ip_src'),
                AIEvents.dst_ip.label('ip_dst'),
                AIEvents.src_port.label('layer4_sport'),
                AIEvents.dst_port.label('layer4_dport'),
                AIEvents.timestamp.label('timestamp'),
                AIEvents.protocol.label('ip_proto')
            ).join(AttackTypes, AttackTypes.id == AIEvents.attack_type)

            re = db.session.query(
                ReportEvents.sig_name,
                ReportEvents.ip_src,
                ReportEvents.ip_dst,
                ReportEvents.layer4_sport,
                ReportEvents.layer4_dport,
                ReportEvents.timestamp.label('timestamp'),
                ReportEvents.ip_proto
            )

            combined_query = ai.union_all(re)   
            
            data = combined_query.order_by(desc('timestamp'))\
            .paginate(page=1, per_page=n, error_out=False)
            
            items = list_2_dict(
                ["sig_name", "ip_src", "ip_dst", "layer4_sport", "layer4_dport", "timestamp", "ip_proto"],
                data.items
            )
            
            res = marshal(items, ReportEventsDto.model_last_alert)
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def get_num_proto_alert(self, args):
        '''
        Get number of alerts that in same proto type

        :return: The num of alerts
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = ReportEvents.query.with_entities(
                ReportEvents.ip_proto, func.count(ReportEvents.ip_proto)
            ).group_by(ReportEvents.ip_proto)\
            .order_by(func.count(ReportEvents.ip_proto).desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)

            items = list_2_dict(["ip_proto", "amount"], data.items)
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def get_proto_alerts(self, protocol, args):
        '''
        Get all alerts of a protocol type
        
        :param ip_proto: protocol type

        :return: All alerts of the protocol type
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            ip_proto = protocol_2_int(protocol)
            
            data = ReportEvents.query.order_by(
                ReportEvents.timestamp.desc()
            ).filter_by(
                ip_proto=ip_proto
            ).paginate(page, pageSize, error_out=False)
            
            items = marshal(data.items, ReportEventsDto.model_info_alert_response)
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())
    
    def get_alerts_ip_src(self, args):
        '''
        Get statistic alerts based on ip source

        :param page: page index

        :param pageSize: num of items in a page

        :return: Info related to ip source.
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            # convert ip_src string to ip_src int type
            data = ReportEvents.query.with_entities(
                ReportEvents.ip_src,

                func.count(distinct(ReportEvents.sid)),
                func.count(ReportEvents.cid),
                func.count(distinct(ReportEvents.signature)),
                func.count(distinct(ReportEvents.ip_dst))
            )\
            .group_by(ReportEvents.ip_src)\
            .order_by(func.count(ReportEvents.cid).desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)

            items = list_2_dict(["ip_src", "sensor", "total", "unique_alerts", "ip_dst"], data.items)
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_statis_ip_src)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def get_alerts_ip_dst(self, args):
        '''
        Get statistic alerts based on ip source
        
        :param page: page index

        :param pageSize: num of items in a page

        :return: Info related to ip source.
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = ReportEvents.query.with_entities(
                ReportEvents.ip_dst,

                func.count(distinct(ReportEvents.sid)), 
                func.count(ReportEvents.cid),
                func.count(distinct(ReportEvents.signature)),
                func.count(distinct(ReportEvents.ip_src))
            )\
            .group_by(ReportEvents.ip_dst)\
            .order_by(func.count(ReportEvents.cid).desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)

            items = list_2_dict(["ip_dst", "sensor", "total", "unique_alerts", "ip_src"], data.items)
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_statis_ip_dst)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def get_statistic_sport(self, args):
        '''
        Get statistic alerts based on source port

        :param page: page index
        
        :param pageSize: num of items in a page

        :return: Info ralated to source port.
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = ReportEvents.query.with_entities(
                ReportEvents.layer4_sport,
                func.count(distinct(ReportEvents.sid)),
                
                func.count(ReportEvents.cid),
                func.count(distinct(ReportEvents.signature)),
                func.count(distinct(ReportEvents.ip_dst)),
                
                func.count(distinct(ReportEvents.ip_dst)),
                func.min(ReportEvents.timestamp),
                func.max(ReportEvents.timestamp)
            )\
            .group_by(ReportEvents.layer4_sport)\
            .order_by(func.count(ReportEvents.cid).desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)

            items = list_2_dict(
                ["port", "sensor", "occurrences", "unique_alerts", "src_addr", "dst_addr", "first", "last"],
                data.items
            )
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_statis_port)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def get_statistic_dport(self, args):
        '''
        Get statistic alerts based on destination port

        :param page: page index
        
        :param pageSize: num of items in a page

        :return: Info ralated to destination port.
        '''
        try: 
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = ReportEvents.query.with_entities(
                ReportEvents.layer4_dport,
                func.count(distinct(ReportEvents.sid)),

                func.count(ReportEvents.cid),
                func.count(distinct(ReportEvents.signature)),
                func.count(distinct(ReportEvents.ip_src)),

                func.count(distinct(ReportEvents.ip_dst)),
                func.min(ReportEvents.timestamp),
                func.max(ReportEvents.timestamp),
            )\
            .group_by(ReportEvents.layer4_dport)\
            .order_by(func.count(ReportEvents.cid).desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)

            items = list_2_dict(
                ["port", "sensor", "occurrences", "unique_alerts", "src_addr", "dst_addr", "first", "last"],
                data.items
            )
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_statis_port)
            }
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(e.__str__())

    def threat_intelligent_table(self, args):
        '''
        Get top events by time from first to last

        :param page: page index
        
        :param pageSize: number of items in page
        
        :param first: the first time to filter

        :param last: the last time to filter

        :return: info events in top of this period time
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            events = db.session.query(
                ReportEvents, SigClass
            ).join(SigClass, SigClass.sig_class_id == ReportEvents.sig_class_id, isouter=True)\
            .join(Country, Country.id==ReportEvents.id_country, isouter=True)\
            .with_entities(
                ReportEvents.timestamp,
                ReportEvents.sig_priority,

                SigClass.sig_class_name,
                ReportEvents.sig_name,
                ReportEvents.ip_src,

                ReportEvents.layer4_sport,
                ReportEvents.ip_dst,
                ReportEvents.layer4_dport,
                Country.code
            ).order_by(ReportEvents.timestamp.desc())\
            .filter(ReportEvents.timestamp>=args.first, ReportEvents.timestamp<=args.last)
            
            if args.priority:
                events = events.filter(ReportEvents.sig_priority==priority_str_int(args.priority))
            if args.ip_src:
                events = events.filter(ReportEvents.ip_src==ip2int(args.ip_src.strip()))
            if args.ip_dst:
                events = events.filter(ReportEvents.ip_dst==ip2int(args.ip_dst.strip()))
            if args.sport: 
                events = events.filter(ReportEvents.layer4_sport==args.sport)
            if args.dport:
                events = events.filter(ReportEvents.layer4_dport==args.dport)
            if args.group:
                events = events.filter(SigClass.sig_class_name==args.group.strip())
            if args.name:
                events = events.filter(ReportEvents.sig_name==args.name.strip())
            
            if args.country != None:
                events = events.filter(Country.code==args.country)

            data = events.paginate(page=page, per_page=pageSize, error_out=False)
            items = list_2_dict(
                ["time", "priority", "threat_class", "threat", "ip_src", "sport","ip_dst", "dport", "country"],
                data.items
            )
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, ReportEventsDto.model_threats_intelligent_table)
            }
            
            return send_result(code=200,data=res)
        except Exception as e:
            return send_error(message=e.__str__())

    def threat_intelligent_chart(self, args):
        '''
        Get top alerts by following param

        :param:

        :return: number alerts of group threats
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            kind = args.kind if args.kind else 0
            
            data = db.session.query(ReportEvents)
            items = []
            res = {}
            
            if kind == 0: # group
                data = data.join(
                    SigClass, SigClass.sig_class_id == ReportEvents.sig_class_id
                ).with_entities(
                    
                    SigClass.sig_class_name,
                    func.count(ReportEvents.cid)
                ).group_by(SigClass.sig_class_name)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = [{"group": x, "amount": y} for x,y in data.items]
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 1: # ip_src
                data = data.with_entities(
                    ReportEvents.ip_src,
                    func.count(ReportEvents.cid)
                ).group_by(ReportEvents.ip_src)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = marshal([{"ip": x, "amount": y} for x, y in data.items], ReportEventsDto.model_top_by_ip)
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 2: # ip_dst
                data = data.with_entities(
                    ReportEvents.ip_dst,
                    func.count(ReportEvents.cid)
                    
                ).group_by(ReportEvents.ip_dst)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = marshal([{"ip": x, "amount": y} for x, y in data.items], ReportEventsDto.model_top_by_ip)
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 3: # sig_name
                data = data.with_entities(
                    ReportEvents.sig_name,
                    
                    func.count(ReportEvents.cid)
                ).group_by(ReportEvents.sig_name)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = [{"sig_name": x, "amount": y} for x, y in data.items]
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 4: # priority
                data = data.with_entities(
                    ReportEvents.sig_priority,
                    
                    func.count(ReportEvents.cid)
                ).group_by(ReportEvents.sig_priority)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = [{"priority": x, "amount": y} for x, y in data.items]
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": marshal(items, ReportEventsDto.model_top_by_priority )
                }
                
            elif kind == 5: # protocol
                data = data.with_entities(
                    ReportEvents.ip_proto,
                    
                    func.count(ReportEvents.cid)
                ).group_by(ReportEvents.ip_proto)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page, pageSize, error_out=False)

                items = marshal([{"protocol": x, "amount": y} for x, y in data.items], ReportEventsDto.model_top_by_protocol)
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 6: # source port
                data = data.with_entities(
                    ReportEvents.layer4_sport,
                    func.count(ReportEvents.cid)
                    
                ).group_by(ReportEvents.layer4_sport)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = [{"port": x, "amount": y} for x,y in data.items]
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 7: # dest port
                data = data.with_entities(
                    ReportEvents.layer4_dport,
                    func.count(ReportEvents.cid)
                    
                ).group_by(ReportEvents.layer4_dport)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)

                items = [{"port": x, "amount": y} for x,y in data.items]
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            elif kind == 8: # country
                data = data.join(
                    Country, Country.id==ReportEvents.id_country, isouter=True
                ).with_entities(
                    
                    Country.name,
                    func.count(ReportEvents.cid)
                ).group_by(Country.name)\
                .order_by(func.count(ReportEvents.cid).desc())\
                .paginate(page=page, per_page=pageSize, error_out=False)
                
                items = [{"country": x, "amount": y} for x,y in data.items]
                res = {
                    "page": data.page,
                    "number_in_page": len(items),
                    
                    "pages": data.pages,
                    "total": data.total,
                    "items": items
                }
                
            else: # unknown
                return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="Kind value must be between 0 -> 8") 
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(message=e.__str__())
    
    def get_cncs(self, args):
        '''
        Get all alerts related to cnc server
        
        :return: list alert info
        '''
        try:
            page = 1 if not args['page'] else args['page']
            pageSize = 15 if not args['pageSize'] else args['pageSize']
            
            data = db.session.query(
                ReportEvents
            ).join(SigClass, SigClass.sig_class_id==ReportEvents.sig_class_id, isouter=True)\
            .with_entities(
                ReportEvents.timestamp,
                ReportEvents.sig_priority,
                
                SigClass.sig_class_name,
                ReportEvents.sig_name,
                
                ReportEvents.ip_src,
                ReportEvents.layer4_sport,
                
                ReportEvents.ip_dst,
                ReportEvents.layer4_dport
            )\
            .filter(ReportEvents.signature==65)\
            .order_by(ReportEvents.timestamp.desc())\
            .paginate(page=page, per_page=pageSize, error_out=False)
            
            items = marshal(list_2_dict(
                ["time", "priority", "threat_class", "threat", "ip_src", "sport","ip_dst", "dport"],
                data.items
            ), ReportEventsDto.model_threats_intelligent_table)
            
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
    
    def cnc_detection(self, args):
        '''
        Get cnc detection info
        
        :return: list cnc detection info
        '''
        if 'first' not in args or 'last' not in args:
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your request must have first and last time to filter')
        try:
            page = 1 if not args['page'] else args['page']
            pageSize = 15 if not args['pageSize'] else args['pageSize']
            
            cnc_ds = db.session.query(
                ReportEvents
            ).join(SigClass, SigClass.sig_class_id==ReportEvents.sig_class_id)\
            .order_by(ReportEvents.timestamp.desc())\
            .with_entities(
                ReportEvents.timestamp,
                ReportEvents.sig_priority,
                
                SigClass.sig_class_name,
                ReportEvents.sig_name,
                
                ReportEvents.ip_src,
                ReportEvents.layer4_sport,
                
                ReportEvents.ip_dst,
                ReportEvents.layer4_dport
            )\
            .filter(ReportEvents.signature==65)\
            .filter(ReportEvents.timestamp>=args['first'], ReportEvents.timestamp<=args['last'])
            
            if args.ip_src:
                cnc_ds = cnc_ds.filter(ReportEvents.ip_src==ip2int(args.ip_src.strip()))
            if args.ip_dst:
                cnc_ds = cnc_ds.filter(ReportEvents.ip_dst==ip2int(args.ip_dst.strip()))
                
            data = cnc_ds.paginate(page=page, per_page=pageSize, error_out=False)

            items = marshal(list_2_dict(
                ["time", "priority", "threat_class", "threat", "ip_src", "sport","ip_dst", "dport"],
                data.items
            ), ReportEventsDto.model_threats_intelligent_table)
            
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
            
    def count_by_country(self, args):
        '''
        Count alert by country
        
        :return:
        '''
        if not args.country:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="Your request doesn't have country query param")
        try:
            country = args.country.strip().upper()

            data = db.session.query(
                ReportEvents
            ).join(Country, Country.id==ReportEvents.id_country)\
            .filter(Country.code==country).count()
            
            return send_result(code=200, data=data)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def get_by_countries(self):
        '''
        Get number of alerts of all countries
        
        :return: list
        '''
        try:
            data = db.session.query(
                Country
            ).join(ReportEvents, Country.id==ReportEvents.id_country, isouter=True)\
            .with_entities(
                
                Country.name,
                Country.code,
                func.count(ReportEvents.cid)
            ).order_by(func.count(ReportEvents.cid).desc())\
            .group_by(Country.name, Country.code).all()
            
            res = [{
                "country": x,
                "code": y,
                "amount": z
                
            } for (x,y,z) in data]
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def get_by_sensor(self, args):
        '''
        Get all alerts ralated to sensor ID
        
        :return: list alerts
        '''
        if not args.sid:
            return send_error(code=ErrorCode.BAD_QUERY_PARAMS, message="Your request doesn't have sensor ID")
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = ReportEvents.query.filter_by(
                sid=args.sid
            ).order_by(ReportEvents.timestamp.desc())\
            .paginate(page=page, per_page=pageSize, error_out=False).items
            
            return send_result(code=200, data=marshal(data, ReportEventsDto.model_info_alert_response))
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def count_by_sensors(self):
        '''
        Get number alerts of sensors
        
        :return:
        '''
        try:
            data = db.session.query(
                ReportEvents
            ).join(Sensor, Sensor.sid == ReportEvents.sid, isouter=True)\
            .join(SensorInfo, SensorInfo.interface == Sensor.interface, isouter=True)\
            .with_entities(
                
                SensorInfo.name,
                func.count(ReportEvents.sid)
            ).group_by(SensorInfo.name).all()
            
            
            res = [{
                "sid": x,
                "amount": y
            } for x,y in data]
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def filter(self, data):
        '''
        Filter alert
        
        :return:
        '''
        if not isinstance(data, dict) or 'ip' not in data:
            return send_error(code=ErrorCode.BAD_REQUEST, message="Your request doestn't have ip")
        if ('first' in data) ^ ('last' in data):
            return send_error(code=ErrorCode.BAD_REQUEST, message="Your request have first time field but not have last time field or vice versa")
        try:
            page = data['page'] if 'page' in data else 1
            pageSize = data['pageSize'] if 'pageSize' in data else 15
            
            data = db.session.query(
                ReportEvents
            ).join(SigClass, ReportEvents.sig_class_id==SigClass.sig_class_id, isouter=True)\
            .join(Country, Country.id==ReportEvents.id_country, isouter=True)\
            .with_entities(
                ReportEvents.timestamp,
                ReportEvents.sig_priority,
                
                SigClass.sig_class_name,
                ReportEvents.sig_name,
                
                ReportEvents.ip_src,
                ReportEvents.layer4_sport,
                
                ReportEvents.ip_dst,
                ReportEvents.layer4_dport,
                Country.name
            ).filter(ReportEvents.ip_src==ip2int(data['ip']))
            
            if 'sport' in data:
                data = data.filter(ReportEvents.layer4_sport==data['sport'])
            if 'dport' in data:
                data = data.filter_by(ReportEvents.layer4_dport==data['dport'])
                
            if 'priority' in data:
                data = data.filter(ReportEvents.priority==priority_str_int(data['priority']))
            if 'first' in data and 'last' in data:
                data = data.filter(ReportEvents.timestamp>=data['first'], ReportEvents.timestamp<=data['last'])
            
            if 'group' in data:
                data = data.filter(SigClass.sig_class_name==data['group'])
            if 'name' in data:
                data = data.filter(ReportEvents.sig_name==data['name'])
            
            if 'country' in data:
                data = data.filter(Country.code==data['country'] or Country.name==data['country'])
            data = data.paginate(page=page, per_page=pageSize, error_out=False)

            items = marshal(list_2_dict(
                ["time", "priority", "threat_class", "threat", "ip_src", "sport","ip_dst", "dport", "country"],
                data.items
            ), ReportEventsDto.model_threats_intelligent_table)
            
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
        