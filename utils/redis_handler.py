import redis
import json

from settings.config import RedisConfig

def set_sender(email, pw):
    try:
        r = redis.Redis(host=RedisConfig.HOST, port=RedisConfig.PORT, db=RedisConfig.DB)
        r.publish(
            'set_sender',
            json.dumps({
                "sender_email": email,
                "sender_pw": pw
            })
        )
        return True, None
    except Exception as e:
        return False, e.__str__()