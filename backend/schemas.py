from pydantic import BaseModel, EmailStr


class AccountRegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class AccountVerifyRequest(BaseModel):
    email: EmailStr
    code: str


class AccountLoginRequest(BaseModel):
    email: EmailStr
    password: str


class StaffRequestCreate(BaseModel):
    token: str
    requested_role: str


class StaffRequestAction(BaseModel):
    request_id: int
    approve: bool


class MakeAdminRequest(BaseModel):
    account_id: int
    role: str


class CreateAppRequest(BaseModel):
    name: str
    version: str = "1.0.0"
    owner_id: int | None = None


class RegisterRequest(BaseModel):
    app_id: str
    app_secret: str
    username: str
    password: str
    license_key: str
    hwid: str
    email: str | None = None


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


class DeleteUserRequest(BaseModel):
    user_id: int


class DeleteLicenseRequest(BaseModel):
    license_id: int


class DeleteAppRequest(BaseModel):
    app_id: str


class AppStatusRequest(BaseModel):
    app_id: str
    status: str