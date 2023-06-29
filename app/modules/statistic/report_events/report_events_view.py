from datetime import datetime
from flask_restx import Resource, inputs
from sqlalchemy.sql.expression import null

from app.modules.statistic.report_events.report_events_controller import ReportEventsController
from app.modules.auth.decorator import token_required, admin_token_required
from app.modules.statistic.report_events.report_events_dto import ReportEventsDto

api = ReportEventsDto.api

last_alerts = api.parser()
last_alerts.add_argument('n', type=int, location='args')

statistic_ip_src = api.parser()
statistic_ip_src.add_argument('page', type=int, location='args')
statistic_ip_src.add_argument('pageSize', type=int, location='args')

statistic_ip_dst = statistic_ip_src.copy()
statistic_sport = statistic_ip_src.copy()
statistic_dport = statistic_ip_src.copy()
statistic_alerts = statistic_ip_src.copy()

threat_intelligent_table = api.parser()
threat_intelligent_table.add_argument('page', type=int, required=False, location='form')
threat_intelligent_table.add_argument('pageSize', type=int, required=False, location='form')
threat_intelligent_table.add_argument('first', type=inputs.datetime_from_iso8601, required=True, location='form')
threat_intelligent_table.add_argument('last', type=inputs.datetime_from_iso8601, required=True, location='form')
threat_intelligent_table.add_argument('priority', type=str, required=False, location='form')
threat_intelligent_table.add_argument('ip_src', type=str, required=False, location='form')
threat_intelligent_table.add_argument('ip_dst', type=str, required=False, location='form')
threat_intelligent_table.add_argument('sport', type=int, required=False, location='form')
threat_intelligent_table.add_argument('dport', type=int, required=False, location='form')
threat_intelligent_table.add_argument('group', type=str, required=False, location='form')
threat_intelligent_table.add_argument('name', type=str, required=False, location='form')
threat_intelligent_table.add_argument('country', type=str, required=False, location='form')

threat_intelligent_chart = statistic_ip_src.copy()
threat_intelligent_chart.add_argument('kind',type=int, required=True, location='args')


cnc_detection = statistic_ip_src.copy()
cnc_detection.add_argument('first', type=inputs.datetime_from_iso8601, required=True, location='form')
cnc_detection.add_argument('last', type=inputs.datetime_from_iso8601, required=True, location='form')
cnc_detection.add_argument('ip_src', type=str, required=False, location='form')
cnc_detection.add_argument('ip_dst', type=str, required=False, location='form')

cnc_pagination = statistic_ip_src.copy()

count_by_country = api.parser()
count_by_country.add_argument('country', type=str, required=True, location='args')

get_by_sensor = statistic_ip_src.copy()
get_by_sensor.add_argument('sid', type=int, required=True, location='args')

get_by_ip = ReportEventsDto.get_by_ip

paginate = statistic_ip_src.copy()


@api.route('')
class ReportEventsList(Resource):
    # @token_required
    @api.expect(paginate)
    @api.response(code=200,model=ReportEventsDto.model_response, description='Model for Report Events')
    def get(self):
        '''
        Return Report Events in the system.
        
        :return: The info of Report Events.
        '''
        args = paginate.parse_args()
        controller = ReportEventsController()
        return controller.get(args=args)


@api.route('/alerts')
class StatisticAlerts(Resource):
    @api.response(code=200, model=ReportEventsDto.model_statistic_alerts, description='')
    @api.expect(statistic_alerts)
    def get(self):
        '''
        Statistic alerts in the system

        :return: statistic info ralated to alerts
        '''
        args = statistic_alerts.parse_args()
        controller = ReportEventsController()
        return controller.get_statistic_alerts(args=args)


@api.route('/total_alerts')
class ReportEventsList(Resource):
    # @token_required
    @api.response(code=200,description='')
    def get(self):
        '''
        Return number alerts in the system
        
        :return: The number of alerts.
        '''
        controller = ReportEventsController()
        return controller.get_total_alerts()

@api.route('/last')
class LastReportEvents(Resource):
    @api.response(code=200, model=ReportEventsDto.model_last_alert, description='Model for show Alerts to UI')
    @api.expect(last_alerts)
    def get(self):
        '''
        Return n last Alerts
        -------------------------

        :return: The info of alerts.
        '''
        args = last_alerts.parse_args()
        controller = ReportEventsController()
        return controller.get_last_alerts(args.n)


@api.route('/proto')
class AmountProtoAlert(Resource):
    @api.expect(paginate)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get number of alerts based on protocol types
        --------------------------------

        :return: Number of alerts
        '''
        args = paginate.parse_args()
        controller = ReportEventsController()
        return controller.get_num_proto_alert(args=args)


@api.route('/proto/<string:protocol>')
class ProtoAlert(Resource):
    @api.expect(paginate)
    @api.response(code=200, description='')
    def get(self, protocol):
        '''
        Get number of alerts based on a protocol type
        -----------------------------------

        :return: Number of alerts
        '''
        args = paginate.parse_args()
        controller = ReportEventsController()
        return controller.get_proto_alerts(protocol=protocol, args=args)
    

@api.route('/ipsrc')
@api.expect(statistic_ip_src)
class IpSrcAlert(Resource):
    @api.response(code=200,description='')
    def get(self):
        '''
        Get number of alerts based on source ip address
        ----------------------------

        :return: Number of alerts
        '''
        args = statistic_ip_src.parse_args()
        controller = ReportEventsController()
        return controller.get_alerts_ip_src(args=args)


@api.route('/ipdst')
@api.expect(statistic_ip_dst)
class IpDstAlert(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get number of alerts based on destination ip address
        ----------------------------------

        :return: Number of alerts
        '''
        args = statistic_ip_dst.parse_args()
        controller = ReportEventsController()
        return controller.get_alerts_ip_dst(args)


@api.route('/sport')
@api.expect(statistic_sport)
class SPortStatistic(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Get number of alerts based on source port
        ----------------------------

        :return: Number of alerts
        '''
        args = statistic_sport.parse_args()
        controller = ReportEventsController()
        return controller.get_statistic_sport(args=args)


@api.route('/dport')
class DPortStatistic(Resource):
    @api.expect(statistic_dport)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get number of alerts based on destination port
        ----------------------------------

        :return: Number of alerts
        '''
        args = statistic_dport.parse_args()
        controller = ReportEventsController()
        return controller.get_statistic_dport(args=args)


@api.route('/threats_intelligent_table')
class ThreatIntelligentTable(Resource):
    @api.response(code=200, description='first and last is required and follow to format: 2012-01-01T23:30:00+02:00')
    @api.expect(threat_intelligent_table)
    def post(self):
        '''
        Get information of alerts to show in table
        ------------------------------

        :return: Information of alerts
        '''
        args = threat_intelligent_table.parse_args()
        controller = ReportEventsController()
        return controller.threat_intelligent_table(
            args=args
        )

@api.route('/threats_intelligent_chart')
class ThreatIntelligentTable(Resource):
    @api.response(code=200, description='')
    @api.expect(threat_intelligent_chart)
    def get(self):
        '''
        Get information of alerts to show in chart
        ---------------------------------

        :return: Information of alerts
        '''
        args = threat_intelligent_chart.parse_args()
        controller = ReportEventsController()
        return controller.threat_intelligent_chart(args)

        
@api.route('/cnc_detection')
class CncDetectionTable(Resource):
    @token_required
    @api.expect(cnc_pagination)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get all alert ralated to cnc server info
        
        :return: list alert info
        '''
        args = cnc_pagination.parse_args()
        controller = ReportEventsController()
        return controller.get_cncs(args=args)
    
    @token_required
    @api.response(code=200, description='')
    @api.expect(cnc_detection)
    def post(self):
        '''
        Get cnc detection information - Filter
        -----------------------------------
        
        :return: cnc detection info
        '''
        args = cnc_detection.parse_args()
        controller = ReportEventsController()
        return controller.cnc_detection(args=args)
    

@api.route('/count_by_country')
class CountByCountry(Resource):
    @token_required
    @api.expect(count_by_country)
    @api.response(code=200, description='')
    def get(self):
        '''
        Count alerts by country
        
        :return:
        '''
        args = count_by_country.parse_args()
        controller = ReportEventsController()
        return controller.count_by_country(args=args)
    
@api.route('/count_by_countries')
class CountByCountries(Resource):
    @api.response(code=200, description='')
    def get(self):
        '''
        Count alerts by country
        
        :return:
        '''
        controller = ReportEventsController()
        return controller.get_by_countries()
    
@api.route('/get_by_sensor')
class GetBySensor(Resource):
    @token_required
    @api.expect(get_by_sensor)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get all alerts related to sensor ID
        
        :return:
        '''
        args = get_by_sensor.parse_args()
        controller = ReportEventsController()
        return controller.get_by_sensor(args=args)

@api.route('/count_by_sensors')
class CountBySensors(Resource):
    @token_required
    @api.response(code=200, description='')
    def get(self):
        '''
        Get number alerts of sensors
        
        :return:
        '''
        controller = ReportEventsController()
        return controller.count_by_sensors()

@api.route('/get_by_ip')
class GetByIp(Resource):
    @token_required
    @api.expect(get_by_ip)
    @api.response(code=200, description='')
    def post(self):
        '''
        Get alert by ip
        
        :return: list alert info
        '''
        data = api.payload
        controller = ReportEventsController()
        return controller.filter(data=data)
