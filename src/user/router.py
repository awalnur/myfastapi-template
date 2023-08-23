import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from config.database import get_db
from src.user.model import Users
from src.user.schemes import User

user_router = APIRouter(prefix='/user', tags=["Users Endpoints"])


@user_router.get('', response_model=User)
def get_users(db: Annotated[Session, Depends(get_db)]):
    users = db.query(Users).first()
    # print(users.roles)
    return users
