from flask_restx import Api

from app.modules import ns_user, ns_auth
from app.modules.sensor import ns_sensor
from app.modules.statistic.event import ns_event

from app.modules.statistic.report_events import ns_revents
from app.modules.policy import ns_policy
from app.modules.system import ns_system

from app.modules.backup import ns_backup
from app.modules.automation import ns_automation
from app.modules.cnc import ns_cnc
from app.modules.setup import ns_setup
from app.modules.log import ns_log
from app.modules.statistic.ai_events import ns_ai
from app.modules.monitor import ns_monitor
from app.modules.cnc_dga import ns_cnc_dga

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY'
    }
}


def init_api():
    api = Api(title='GSM APIs',
              version='0.1',
              description='The GSM APIs',
              authorizations=authorizations,
              security='apikey'
              )

    api.add_namespace(ns_auth, '/api/v1/auth')
    api.add_namespace(ns_user, '/api/v1/user')
    api.add_namespace(ns_sensor, '/api/v1/sensor')
    api.add_namespace(ns_event, '/api/v1/statistic/event')

    api.add_namespace(ns_revents, '/api/v1/statistic/revents')
    api.add_namespace(ns_policy, '/api/v1/policy')
    api.add_namespace(ns_system, '/api/v1/system')
    api.add_namespace(ns_backup, '/api/v1/backup')
    
    api.add_namespace(ns_automation, '/api/v1/automation')
    api.add_namespace(ns_cnc, '/api/v1/cnc')
    api.add_namespace(ns_setup, '/api/v1/setup')
    api.add_namespace(ns_log, '/api/v1/log')
    
    api.add_namespace(ns_ai, '/api/v1/statistic/ai')
    api.add_namespace(ns_monitor, '/api/v1/monitor')
    api.add_namespace(ns_cnc_dga, '/api/v1/cnc_dga')
    return api 
