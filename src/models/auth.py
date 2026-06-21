from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str
    totp: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str