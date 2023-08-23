import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # DEBUG: bool
    # DB_HOST: str
    # DB_PORT: int
    # DB_USER: str
    # DB_PASSWORD: str
    # DB_NAME: str

    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    ALGORITHM: str
    REFRESH_TOKEN_EXPIRE_DAYS: int
    REFRESH_TOKEN_SECRET_KEY: str

    class Config:
        env_file = ".env"


settings = Settings()
