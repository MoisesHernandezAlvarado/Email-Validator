from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "Email Validator API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    
    # Configuraciones adicionales
    MAX_BATCH_SIZE: int = 100
    SMTP_TIMEOUT: int = 10
    DNS_TIMEOUT: int = 5
    
    # Configuraciones de rate limiting (opcional)
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 60  # segundos
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()