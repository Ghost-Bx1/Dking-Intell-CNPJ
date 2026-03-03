import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Flask session (usado para autenticação de páginas)
    SECRET_KEY           = os.environ.get("SECRET_KEY",
                               "dking-flask-secret-key-minimo-32-chars-2025!!")
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = "Lax"
    SESSION_COOKIE_SECURE    = False   # True em produção HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    DEBUG    = os.environ.get("DEBUG", "False").lower() == "true"
    TESTING  = False

    # Database
    SQLALCHEMY_DATABASE_URI       = os.environ.get("DATABASE_URL", "sqlite:///dking.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS      = {"pool_pre_ping": True}

    # JWT (usado só para chamadas diretas à API)
    JWT_SECRET_KEY               = os.environ.get("JWT_SECRET_KEY",
                                       "dking-jwt-secret-key-minimo-32-chars-2025!!")
    JWT_ACCESS_TOKEN_EXPIRES     = timedelta(seconds=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES",  900)))
    JWT_REFRESH_TOKEN_EXPIRES    = timedelta(seconds=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", 604800)))
    JWT_TOKEN_LOCATION           = ["cookies"]
    JWT_COOKIE_SECURE            = False   # True em produção HTTPS
    JWT_COOKIE_SAMESITE          = "Lax"
    JWT_COOKIE_CSRF_PROTECT      = False   # Desativado; SameSite=Lax protege em dev

    # Segurança
    BCRYPT_ROUNDS      = int(os.environ.get("BCRYPT_ROUNDS",      12))
    MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS",  5))
    LOCKOUT_MINUTES    = int(os.environ.get("LOCKOUT_MINUTES",    15))

    # CORS
    ALLOWED_ORIGINS = os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:5000,http://127.0.0.1:5000"
    ).split(",")

    # Redis (vazio = usa memória local)
    REDIS_URL = os.environ.get("REDIS_URL", "")

    # APIs externas
    INVERTEXTO_TOKEN = os.environ.get("INVERTEXTO_TOKEN", "")

    FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "False").lower() == "true"


class DevelopmentConfig(Config):
    DEBUG                    = True
    SESSION_COOKIE_SECURE    = False
    JWT_COOKIE_SECURE        = False
    JWT_COOKIE_CSRF_PROTECT  = False
    FORCE_HTTPS              = False


class ProductionConfig(Config):
    DEBUG                    = False
    SESSION_COOKIE_SECURE    = True
    SESSION_COOKIE_SAMESITE  = "Strict"
    JWT_COOKIE_SECURE        = True
    JWT_COOKIE_SAMESITE      = "Strict"
    JWT_COOKIE_CSRF_PROTECT  = True
    FORCE_HTTPS              = True


config_map = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "default":     DevelopmentConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, config_map["default"])