from pydantic import BaseModel


class UnprocessedEntity(BaseModel):
    error: str
    message: str


class BadRequest(BaseModel):
    detail: str
