import uuid
from typing import Type

from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from src.user.model import Users
from src.user.schemes import User


def get_user(db: Session, username) -> User:
    try:
        user = db.query(Users).filter(Users.username == username).first()
        res = User.model_validate(user) if user else None
    except NoResultFound:
        res = None

    return res


def get_user_by_id(db: Session, user_id: str) -> Type[User] | None:
    user_uuid = uuid.UUID(user_id).hex
    try:
        user = db.query(Users).filter(Users.user_id == user_uuid).first()
        res = User.model_validate(user)
    except NoResultFound:
        res = None
    return res
