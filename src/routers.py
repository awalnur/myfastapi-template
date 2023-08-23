from src.auth.router import auth_router
from src.user.router import user_router


def routers(app):
    app.include_router(auth_router, prefix="/api")
    app.include_router(user_router, prefix="/api")
    return app
