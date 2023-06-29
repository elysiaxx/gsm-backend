from flask_restx import Namespace

from app.modules.common.dto import Dto


class SystemDto(Dto):
    name = 'system'
    api = Namespace(name)
    
    