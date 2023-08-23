import os
from pathlib import Path

from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

# from config.custom_logging import CustomizeLogger
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.responses import ORJSONResponse
from fastapi_pagination import add_pagination
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.routers import routers


def app():

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title="Template",
            version="v0.0.1-dev",
            description="Template",
            routes=app.routes,

        )

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    config_path = Path(os.path.join('log_config.json'))
    print(config_path)
    # logger = CustomizeLogger.make_logger(config_path)

    app = FastAPI(
        default_response_class=ORJSONResponse,
        title="Project Name ",
        swagger_ui_parameters={
            "defaultModelsExpandDepth": -1,
            "displayRequestDuration": True,
        }
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition"],
        max_age=600
    )
    app.openapi = custom_openapi
    # app.logger = logger
    app.add_exception_handler(RequestValidationError, validation_exception_handler)  # custom exception handler
    add_pagination(app)
    routers(app)
    return app


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": "Validation Error",
                 "detail": f"{exc.errors()[0]['type']}, {exc.errors()[0]['loc'][1]} {exc.errors()[0]['msg']}"},
    )
