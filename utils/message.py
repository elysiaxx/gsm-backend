# Định nghĩa các messages theo các error codes tương ứng.

messages = dict()
messages['4000'] = 'Bad Request'
messages['4001'] = 'Invalid query params'#'User not found'
messages['4002'] = 'User already exists'

messages['4010'] = 'Unauthorized'
messages['4011'] = 'No such user'
messages['4012'] = 'Wrong user credentials'
messages['4013'] = 'Authorize token is expired'

messages['4014'] = 'Invalid authorize token'
messages['4030'] = 'Forbidden'
messages['4031'] = 'Permission deny'

messages['4040'] = 'Not found'
messages['4041'] = 'Not found sender credential'

messages['4050'] = 'Method not allowed'
messages['4060'] = 'Not acceptable'
messages['4080'] = 'Request timeout'
messages['5000'] = 'Internal server error'

messages['4100'] = 'File name alread exist'
