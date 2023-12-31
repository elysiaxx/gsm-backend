# Định nghĩa các error codes để sau truyền vào trong các đoạn phân hệ.

class ErrorCode:
    BAD_REQUEST = 4000
    BAD_QUERY_PARAMS = 4001
    EXISTS_USER_ERROR = 4002

    UNAUTHORIZED = 4010
    NO_SUCH_USER = 4011
    WRONG_CREDENTIALS = 4012
    EXPIRED_AUTHORIZE_TOKEN = 4013

    INVALID_TOKEN = 4014
    FORBIDDEN = 4030
    PERMISSION_DENY = 4031
    
    NOT_FOUND = 4040
    NOT_FOUND_SENDER_CREDENTIAL = 4041

    METHOD_NOT_ALLOWED = 4050
    NOT_ACCEPTABLE = 4060
    REQUEST_TIMEOUT = 4080
    INTERNAL_SERVER_ERROR = 5000

    SERVICE_ALREADY_RUNNING = 4003
    SERVICE_HAVE_STOPPED = 4004
    RULE_FILE_ALREADY_EXIST = 4100