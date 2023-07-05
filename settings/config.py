import os


class Config:
    DEBUG = False
    SECRET_KEY = os.environ.get('FLASK_SECRET', 'f495b66803a6512d')
    SECURITY_SALT = os.environ.get('FLASK_SALT', '14be1971fc014f1b84')

    APP_DIR = os.path.abspath(os.path.dirname(__file__))
    LOG_PATH = '/var/log/gsm/gsm.log'
    PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, os.pardir))
    STATIC_FOLDER = os.path.join(PROJECT_ROOT, 'static')
    IMAGE_FOLDER = os.path.join(STATIC_FOLDER, 'images')
    AVATAR_FOLDER = os.path.join(IMAGE_FOLDER, 'avatars')

    BCRYPT_LOG_ROUNDS = 13
    DEBUG_TB_ENABLED = False  # Disable Debug toolbar
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    
    AUTH_TOKEN = '0001f9f05a59574bbf602d6117ad6d2d'


class DevelopmentConfig(Config):
    DEBUG = True
    DEBUG_TB_ENABLED = True
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://' + os.getenv("MYSQL_USERNAME", "root") + ":"\
    + os.getenv("MYSQL_PASSWORD", "Gsm%402022") + "@" + os.getenv("MYSQL_HOST", "localhost") + ":3306/gsm"
    MONGODB_SETTINGS = {
        'host': 'mongodb://' + os.getenv('MONGO_USERNAME','root') + ':' \
        + os.getenv("MONGO_PASSWORD", "Gsm%402022") + "@" + os.getenv("MONGO_HOST", "localhost") + ":27017/gsm?authSource=admin",
        'db': 'gsm'
    }


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://' + os.getenv("MYSQL_USERNAME", "root") + ":"\
    + os.getenv("MYSQL_PASSWORD", "Gsm%402022") + "@" + os.getenv("MYSQL_HOST", "localhost") + ":3306/gsm"
    MONGODB_SETTINGS = {
        'host': 'mongodb://' + os.getenv('MONGO_USERNAME','root') + ':' \
        + os.getenv("MONGO_PASSWORD", "Gsm%402022") + "@" + os.getenv("MONGO_HOST", "localhost") + ":27017/gsm?authSource=admin",
        'db': 'gsm'
    }
    



class TestConfig(Config):
    """Test configuration."""

    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    BCRYPT_LOG_ROUNDS = 4  # For faster tests; needs at least 4 to avoid "ValueError: Invalid rounds"


class RedisConfig(Config):
    """
    Redis Configuration
    """
    
    HOST = os.getenv("REDIS_HOST", "localhost")
    PORT = 6379
    DB = 0


config_by_name = dict(
    dev=DevelopmentConfig,
    prod=ProductionConfig
)

key = Config.SECRET_KEY
