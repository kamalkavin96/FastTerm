from pydantic import BaseModel


class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False