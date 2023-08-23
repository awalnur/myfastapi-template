from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Security
from fastapi.security import (
    OAuth2PasswordBearer,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError
from redis import Redis
from sqlalchemy.orm import Session

from config.config import settings
from config.database import get_db, get_redis
from src.auth.schemes import TokenData
from src.exceptions import ForbiddenException
from src.user.schemes import User
from src.user.service import get_user, get_user_by_id

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/token",
    scopes={"me": "Read information about the current user.", "items": "Read items."},
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(redis_con: Redis, data: dict, expires_delta: timedelta | None = None,
                        ):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    redis_con.setex(name=f"userid_a_{to_encode.get('sub')}", time=5, value=str(encoded_jwt))
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None,
                         ):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_TOKEN_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def revoke_access_token():
    pass


def revoke_refresh_token():
    pass


async def get_current_user(
        db: Annotated[Session, Depends(get_db)],
        security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)],
        rcon: Annotated[Redis, Depends(get_redis)]
):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise ForbiddenException

        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, user_id=user_id)
    except (JWTError, ValidationError):
        raise ForbiddenException
    user = get_user_by_id(db, user_id=token_data.user_id)
    if user is None:
        raise ForbiddenException
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise ForbiddenException
    return user


async def get_current_active_user(
        current_user: Annotated[User, Security(get_current_user, scopes=["me"])]
):
    if current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def extract_refresh_token_data(db, token_data: str):
    try:
        payload = jwt.decode(token_data, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise ForbiddenException
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, user_id=user_id)
    except (JWTError, ValidationError):
        raise ForbiddenException
    user = get_user_by_id(db, user_id=token_data.user_id)
    if user is None:
        raise ForbiddenException
    return user


def set_redis_r_token(user_id: str, r_token: str, redis_con: Redis):
    redis_con.setex(f"userid_r_{user_id}", value=r_token, time=600)
