from pydantic import BaseModel


class CreateAppRequest(BaseModel):
    name: str
    version: str = "1.0.0"


class RegisterRequest(BaseModel):
    app_id: str
    app_secret: str
    username: str
    password: str
    license_key: str
    hwid: str


class LoginRequest(BaseModel):
    app_id: str
    app_secret: str
    username: str
    password: str
    hwid: str


class ValidateRequest(BaseModel):
    token: str
    hwid: str


class LogoutRequest(BaseModel):
    token: str


class BanUserRequest(BaseModel):
    user_id: int
    banned: bool = True


class ResetHWIDRequest(BaseModel):
    user_id: int


class ExtendUserRequest(BaseModel):
    user_id: int
    days: int