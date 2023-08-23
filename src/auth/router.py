from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordRequestForm, SecurityScopes
from redis import Redis
from sqlalchemy.orm import Session

from config.config import settings
from config.database import get_db, get_redis
from src.auth.schemes import AccessToken, UserLogin, Token, LogoutModel
from src.auth.security import authenticate_user, create_access_token, \
    get_current_active_user, get_current_user, extract_refresh_token_data, set_redis_r_token, create_refresh_token, \
    revoke_refresh_token, revoke_access_token
from src.auth.service import create_credentials
from src.exceptions import CredentialsException
from src.response_model import BadRequest, UnprocessedEntity
from src.user.schemes import User

auth_router = APIRouter(prefix='/auth', tags=['Authentication Endpoints'])


@auth_router.post("/token", response_model=Token, include_in_schema=False)
async def login_for_access_token(
        db: Annotated[Session, Depends(get_db)],
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
        redis_con: Annotated[Redis, Depends(get_redis)]
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    res = create_credentials(db, redis_con, user)
    return res


@auth_router.post("/login", response_model=Token, responses={
    422: {"model": UnprocessedEntity},
    400: {"model": BadRequest}

})
def login(db: Annotated[Session, Depends(get_db)], payload: UserLogin,
          redis_con: Annotated[Redis, Depends(get_redis)]) -> Token:
    user = authenticate_user(db, payload.username, payload.password)

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    res = create_credentials(db, redis_con, user, )
    return res


@auth_router.post("/refresh", response_model=AccessToken, responses={422: {"model": UnprocessedEntity},
                                                                     400: {"model": BadRequest}
                                                                     })
def refresh_token_data(db: Annotated[Session, Depends(get_db)],
                       redis_con: Annotated[Redis, Depends(get_redis)], refresh_token: str):
    user = extract_refresh_token_data(db, token_data=refresh_token)
    if not user:
        raise CredentialsException

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    role = [Role.name for Role in user.roles]
    access_token = create_access_token(
        data={"sub": str(user.user_id), "scopes": role},
        expires_delta=access_token_expires,
        redis_con=redis_con
    )

    res = {
        "access_token": access_token,
        "token_type": "bearer"
    }
    return res


@auth_router.post("/logout")
async def logout(db: Annotated[Session, Depends(get_db)], data: LogoutModel,
                 redis_con: Annotated[Redis, Depends(get_redis)]):
    """

    this endpoint to revoke a user session.
    body request \n
    - ``device``    : to delete session from current device or all devices. this body is optional and default value is None \n
    - ``access_token`` : to revoke session from current device\n
    - `refresh_token` : it's used to revoke the refresh token. if the device is not set, it's just logging out from current device. \n
    """

    revoke_access_token(redis_conn=redis_con, access_token=data.access_token)
    revoke_refresh_token(db, refresh_token=data.refresh_token)
    return {"detail": "Logout Successfully"}


@auth_router.get("/users/me/", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@auth_router.get("/users/me/items/")
async def read_own_items(
        current_user: Annotated[User, Security(get_current_active_user, scopes=["items"])]
):
    return [{"item_id": "Foo", "owner": current_user.username}]
