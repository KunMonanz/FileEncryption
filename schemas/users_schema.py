from pydantic import BaseModel


class UserRegisterSchema(BaseModel):
    username: str
    password: str


class UserLoginSchema(BaseModel):
    username: str
    password: str


class UserResponseSchema(BaseModel):
    username: str
    role: str

    class Config:
        from_attributes = True


class DecryptPrivateKeySchema(BaseModel):
    password: str


class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str
