import dataclasses
from typing import List, Any
from uuid import UUID

from pydantic import BaseModel, EmailStr
from sqlalchemy import DateTime


class RoleBase(BaseModel):
    name: str
    description: str | None = None


class RoleCreate(RoleBase):
    pass


class Role(RoleBase):
    role_id: int

    class Config:
        from_attributes = True


class UserBase(BaseModel):
    username: str
    email: EmailStr


class UserCreate(UserBase):
    hashed_password: str


class User(UserBase):
    user_id: UUID
    hashed_password: str
    is_active: bool
    roles: List[Role] | None = None

    class Config:
        from_attributes = True
