from datetime import datetime
from fastapi import Depends
import jwt
import os
from pwdlib import PasswordHash
from dotenv import load_dotenv
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/accounts/login")

load_dotenv()


password_hash = PasswordHash.recommended()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"


def create_access_token(username: str, role: str):
    expire = datetime.now()
    payload = {
        "user": username,
        "role": role,
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, ALGORITHM)  # type: ignore


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token,
                             SECRET_KEY,  # type: ignore
                             algorithms=[
                                 ALGORITHM
                             ]
                             )
        username: str = payload.get("user")
        role = payload.get("role")
        if username is None:
            return None
        return {
            "username": username,
            "role": role
        }
    except jwt.PyJWTError:
        return None
