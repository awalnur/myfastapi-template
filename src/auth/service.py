from datetime import timedelta, datetime

from fastapi import HTTPException
from redis import Redis
from sqlalchemy.orm import Session

from config.config import settings
from src.auth.schemes import Token
from src.auth.security import create_access_token, create_refresh_token, set_redis_r_token
from src.user.model import RefreshToken


def create_credentials(db: Session, redis_con: Redis, user) -> Token:
    role = [Role.name for Role in user.roles]
    access_token = create_access_token(
        data={"sub": str(user.user_id), "scopes": role},
        redis_con=redis_con
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.user_id)}
    )
    refresh_token_save = RefreshToken(refresh_token=refresh_token, user_id=user.user_id,
                                      expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    try:
        db.query(RefreshToken).filter(RefreshToken.user_id==user.user_id).count()

        db.add(refresh_token_save)
        db.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=e)
    res = Token(access_token=access_token, refresh_token=refresh_token)
    # print(res)

    return res
