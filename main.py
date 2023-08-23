from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

from config.database import engine
from src.app import app
from src.user import model

model.Base.metadata.create_all(bind=engine)

app = app()


@app.get("/test-health-check", include_in_schema=False)
async def root():
    raise HTTPException(status_code=400, detail='sda')
    # return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}
