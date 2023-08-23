import datetime
import uuid

from sqlalchemy import Column, Integer, Text, String, func, DateTime, Boolean, Table, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from config.config import settings
from config.database import Base

user_role_association = Table('user_role_association',
                              Base.metadata,
                              Column('user_id', UUID, ForeignKey('tbl_users.user_id'), primary_key=True),
                              Column('role_id', Integer, ForeignKey('tbl_roles.role_id'), primary_key=True)
                              )


class Users(Base):
    __tablename__ = 'tbl_users'
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4())
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())

    # Additional columns for soft delete
    is_deleted = Column(Boolean, default=False)
    deleted_at = Column(DateTime, nullable=True)

    # Define the many-to-many relationship with roles
    roles = relationship('Roles', secondary=user_role_association, back_populates='users')
    refresh_tokens = relationship('RefreshToken', back_populates='user')

    def delete(self):
        self.is_deleted = True
        self.deleted_at = func.now()

    def restore(self):
        self.is_deleted = False
        self.deleted_at = None


class RefreshToken(Base):
    __tablename__ = 'tbl_refresh_token'

    refresh_token = Column(String(255), primary_key=True)
    expires_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow() + datetime.timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    device = Column(String(255), nullable=True)

    # User relationship
    user_id = Column(UUID(as_uuid=True), ForeignKey('tbl_users.user_id'), nullable=False)
    user = relationship('Users', back_populates='refresh_tokens')


class Roles(Base):
    __tablename__ = 'tbl_roles'
    role_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    # Define the many-to-many relationship with users
    users = relationship('Users', secondary=user_role_association, back_populates='roles')
