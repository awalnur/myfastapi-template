#
import uuid

from src.auth.security import get_password_hash

DEFAULT_ROLES = [
    {'name': 'admin'},
    {'name': 'user'},
    {'name': 'guest'},
]

user_id = uuid.uuid4()
user_id2 = uuid.uuid4()
user_id_admin = uuid.uuid4()
DEFAULT_USERS = [
    {
        'user_id': user_id,
        'username': 'john_doe',
        'email': 'john@example.com',
        'password_hash': get_password_hash('defaultpassword'),
        'is_active': True
    },
    {
        'user_id': user_id2,
        'username': 'jane_smith',
        'email': 'jane_smith@example.com',
        'password_hash': get_password_hash('defaultpassword'),
        'is_active': True
    },
    {
        'user_id': user_id_admin,
        'username': 'admin',
        'email': 'admin@example.com',
        'password_hash': get_password_hash('defaultpassword'),
        'is_active': True
    }
]

DEFAULT_USER_ROLES = [
    {
        'user_id': user_id,
        'role_id': 3
    },
    {
        'user_id': user_id2,
        'role_id': 2
    },
    {
        'user_id': user_id_admin,
        'role_id': 1
    }

]

