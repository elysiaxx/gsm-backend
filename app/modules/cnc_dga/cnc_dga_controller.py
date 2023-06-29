from xmlrpc.client import Boolean
from flask_restx import marshal

from app.app import db
from datetime import datetime, timedelta

from app.modules.cnc_dga.cnc_dga_dto import CncDgaDto
from app.modules.cnc_dga.cnc_dga import CncDga

from utils.response import send_error, send_result
from utils.message_code import ErrorCode


class CncDgaController():
    
    def get(self, args):
        '''
        Get all cnc dga alerts
        '''
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = CncDga.query.order_by(CncDga.timestamp.desc()).paginate(page=page, per_page=pageSize, error_out=False)
            items = marshal(data.items, CncDgaDto.model_response)
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": items
            }
            return send_result(code=200, data=res)
        except Exception as e:
            print(e.__str__())
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())
    
    def filter(self, args):
        '''
        filtering ai events
        
        :return: 
        '''
        if not isinstance(args, dict):
            return send_error(code=ErrorCode.BAD_REQUEST, message='Your data must be an instance of dictionary')
        if (args.first is not None) != (args.last is not None):
            return send_error(code=400, message="fist in request but last not in request is not accept and vice versa, please fill both or not")
        try:
            page = args.page if args.page else 1
            pageSize = args.pageSize if args.pageSize else 15
            
            data = db.session.query(
                CncDga
            )

            if args.domain:
                data = data.filter(CncDga.domain==args.domain.strip())
                
            if (args.first is not None) and (args.last is not None):
                data = data.filter(
                    CncDga.timestamp>=args.first,
                    CncDga.timestamp<=args.last
                ).order_by(CncDga.timestamp.desc())
            
            data = data.paginate(page=page, per_page=pageSize, error_out=False)

            items = [x for x in data.items]
            
            res = {
                "page": data.page,
                "number_in_page": len(items),
                
                "pages": data.pages,
                "total": data.total,
                "items": marshal(items, CncDgaDto.model_response)
            }
            
            return send_result(code=200, data=res)
        except Exception as e:
            return send_error(code=ErrorCode.INTERNAL_SERVER_ERROR, message=e.__str__())