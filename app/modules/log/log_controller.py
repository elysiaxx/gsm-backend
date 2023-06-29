

from flask_restx import marshal

from app.modules.log.log_dto import LogDto

from utils.message_code import ErrorCode
from utils.response import send_error, send_result
from utils.util import get_log, parse_logs


class LogController():
    
    def get(self, args):
        '''
        Get log infos
        
        :return: list log infos
        '''
        try:
            logs = get_log(limit=args.limit)
            res, err = parse_logs(logs)
            if not res:
                return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=err)

            return send_result(code=200, data=marshal(res, LogDto.model_response))            
        except Exception as e:
            return send_error(code=ErrorCode)
    
    