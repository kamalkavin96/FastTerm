from pydantic import BaseModel


class ProfileRequest(BaseModel):
    name: str
    host: str
    port: int = 22
    ssh_username: str