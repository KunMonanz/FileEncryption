from fastapi import Depends, HTTPException, status
from datetime import datetime
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


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": True}
        )
        username: str | None = payload.get("user")
        role = payload.get("role")

        if username is None:
            raise credentials_exception

        return {
            "username": username,
            "role": role
        }

    except jwt.PyJWTError:
        raise credentials_exception


def get_admin_user(token: str = Depends(oauth2_scheme)):
    user = get_current_user(token)

    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    return user
