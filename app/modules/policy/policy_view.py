from flask import request
from flask_restx import Resource
from werkzeug.datastructures import FileStorage

from app.modules.policy.policy_controller import PolicyController
from app.modules.policy.policy_dto import PolicyDto
from app.modules.auth.decorator import token_required, admin_token_required

api = PolicyDto.api

create_policy_request = PolicyDto.model_request
create_policy_response = PolicyDto.model_response

file_request = PolicyDto.model_file_request
file_response = PolicyDto.model_file_response

rule_request = PolicyDto.model_rule_request
rule_response = PolicyDto.model_rule_response

file_upload = api.parser()
file_upload.add_argument('file', location='files',
                           type=FileStorage, required=True, help='The file to upload')
file_upload.add_argument('file_name', location='form', type=str, required=True, help='The file name')
file_upload.add_argument('file_type', location='form', type=str, required=True, help='The rule file type')
file_upload.add_argument('file_status', location='form', type=bool, required=True, help='The rule file status')
file_upload.add_argument('overwrite', location='form', type=bool, required=False)

get_rules = api.parser()
get_rules.add_argument('page', location='args', type=int, required=False, help='Page index')
get_rules.add_argument('pageSize', location='args', type=int, required=False, help='Num element per page')
get_rules.add_argument('file_id', location='args', type=int, required=True, help='Rule File ID')

policy_line = api.parser()
policy_line.add_argument('policy', type=str, required=False, location='form')

pagination = api.parser()
pagination.add_argument('page', location='args', type=int, required=False, help='Page index')
pagination.add_argument('pageSize', location='args', type=int, required=False, help='Num element per page')

# @api.route('')
# class PolicyList(Resource):
    
#     # @token_required
#     @api.response(code=200, description='')
#     def get(self):
#         pass

#     @admin_token_required
#     @api.expect(create_policy_request)
#     @api.response(code=200, description='')
#     def post(self):
#         '''
#         Create new policy.
#         -------------------
#         All data to create a new user is stored in dictionary form.

#         :return: New Policy is created successfully and error vice versa.
#         '''
#         # data = api.payload
#         # controller = PolicyController()
#         # return controller.create(data=data)
    
@api.route('/parse')
class ParsePolicy(Resource):
    @token_required
    @api.response(code=200, description="")
    @api.expect(policy_line)
    def post(self):
        '''
        Parse policy string type to policy object
        
        :return: object
        '''
        args = policy_line.parse_args()
        controller = PolicyController()
        return controller.parse_policy(args.policy)
    
@api.route('/file')
class FileList(Resource):
    
    @token_required
    @api.response(code=200, model=file_response, description='')
    @api.expect(pagination)
    def get(self):
        '''
        Get rule files information
        
        :return: list information of rule file.
        '''
        args = pagination.parse_args()
        controller = PolicyController()
        return controller.get_file(args=args)
    
    # not use currently
    @token_required
    @api.expect(file_upload)
    @api.response(code=200, model=file_request, description='')
    def post(self):
        '''
        Create rule file information
        
        :return: rule file inforation if created successfully and vice versa
        '''
        args = file_upload.parse_args()
        controller = PolicyController()
        return controller.create_file(args=args, req=request)

@api.route('/file/total')
class TotalFile(Resource):
    @token_required
    def get(self):
        '''
        Get number of rule files in the system
        ------------------------------
        
        :return: number of rule files
        '''
        controller = PolicyController()
        return controller.get_total_file()


@api.route('/file/<int:id>')
class File(Resource):
    @token_required
    @api.response(code=200, model=file_response, description='')
    def get(self, id):
        '''
        Get rule file information by file ID
        
        :param id: file ID
        
        :return: rule file information
        '''
        controller = PolicyController()
        return controller.get_file_by_id(object_id=id)
    
    @token_required
    @api.expect(file_request)
    @api.response(code=200, model=file_response, description='')
    def put(self, id):
        '''
        Update rule file
        
        :param id: file ID
        
        :return:
        '''
        data = api.payload
        controller = PolicyController()
        return controller.update_file(object_id=id, data=data, req=request)
    
    @token_required
    def delete(self, id):
        '''
        Delete rule file
        
        :param id: file ID
        
        :return: True if successfully and vice versa
        '''
        controller = PolicyController()
        return controller.delete_file(object_id=id)
    
@api.route('/file/<string:name>')
class FileByName(Resource):
    @token_required
    @api.response(code=200, model=file_response, description='')
    def get(self, name):
        '''
        Get rule file information by file name
        
        :param name: file name
        
        :return: rule file information
        '''
        controller = PolicyController()
        return controller.get_file_by_name(object_name=name)
    
@api.route('/rule')
class RuleList(Resource):
    @token_required
    @api.expect(get_rules)
    @api.response(code=200, description='')
    def get(self):
        '''
        Get rules of file by file ID
        
        :param file_id: file ID
        
        :return: list rules of rule file
        '''
        args = get_rules.parse_args()
        controller = PolicyController()
        return controller.get_rule(args=args)
    
    @token_required
    @api.expect(rule_request)
    @api.response(code=200, model=rule_response, description='')
    def post(self):
        '''
        Create rule and add this rule into rule of rule file by file ID
        
        :param file_id: file ID
        
        :return: rule information if created successfully and vice versa
        '''
        data = api.payload
        controller = PolicyController()
        return controller.create_rule(data=data, req=request)

@api.route('/rule/total')
class TotalRule(Resource):
    def get(self):
        '''
        Get number of rule in the system
        ---------------------------------
        
        :return: number of rule
        '''
        controller = PolicyController()
        return controller.get_total_rule()
    
@api.route('/rule/recent_update')
class RecentUpdate(Resource):
    def get(self):
        '''
        Get recent update related to rule in the system
        ----------------------------
        
        :return: datetime
        '''
        controller = PolicyController()
        return controller.get_recent_update()


@api.route('/rule/<int:id>')
class Rule(Resource):
    @token_required
    def get(self, id):
        '''
        Get rule by rule ID
        
        :param id: rule ID
        
        :return: Rule information
        '''
        controller = PolicyController()
        return controller.get_rule_by_id(object_id=id)
    
    @token_required
    @api.expect(rule_request)
    @api.response(code=200, model=rule_response, description='')
    def put(self, id):
        '''
        Update rule
        
        :param id: rule ID
        
        :return: Rule information
        '''
        data = api.payload
        controller = PolicyController()
        return controller.update_rule(object_id=id, data=data, req=request)
          
    @token_required
    def delete(self, id):
        '''
        Delete rule in the system
        
        :param id: rule ID
        
        :return:
        '''
        controller = PolicyController()
        return controller.delete_rule(object_id=id, req=request)