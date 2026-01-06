from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from fastapi import APIRouter, Depends, HTTPException

from schemas.users_schema import (
    ChangePasswordSchema,
    DecryptPrivateKeySchema,
    UserLoginSchema,
    UserRegisterSchema
)

from crud.users_crud import (
    change_password_crud,
    create_user,
    search_for_user_username,
    compare_user_password
)

from encryption import password_hash
from database import get_db
from auth import create_access_token, get_current_user


router = APIRouter(prefix="/api/v1/accounts")

USER_DOES_NOT_EXIST = "User does not exist"


@router.post("/register")
def sign_up(
    users_signup_request: UserRegisterSchema,
    db=Depends(get_db)
):

    auth_salt = get_random_bytes(16)
    crypto_salt = get_random_bytes(16)

    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.public_key().export_key()

    hashed_password = password_hash(users_signup_request.password, auth_salt)

    kek = PBKDF2(
        users_signup_request.password,
        crypto_salt,
        dkLen=32,
        count=300_000
    )
    cipher = AES.new(kek, AES.MODE_EAX)
    encrypted_private_key, tag = cipher.encrypt_and_digest(private_key)

    username = users_signup_request.username.strip().lower()

    password_verify = search_for_user_username(
        username,
        db
    )

    if password_verify:
        raise HTTPException(
            detail="User already exists",
            status_code=409
        )

    user_created = create_user(
        username=username,
        hashed_password=hashed_password,
        auth_salt=auth_salt,
        crypto_salt=crypto_salt,
        public_key=public_key,
        encrypted_private_key=encrypted_private_key,
        private_key_tag=tag,
        private_key_nonce=cipher.nonce,
        db=db
    )
    if not user_created:
        raise HTTPException(
            detail="Error registering user",
            status_code=400
        )

    return {
        "message": "Registration is successful"
    }


@router.post("/login")
def login(
    users_login_request: UserLoginSchema,
    db=Depends(get_db)
):
    username = users_login_request.username.strip().lower()

    user = search_for_user_username(username, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    password_valid = compare_user_password(
        user.auth_salt,  # type: ignore
        users_login_request.password,
        user.hashed_password  # type: ignore
    )

    if not password_valid:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        username=user.username,  # type: ignore
        role=user.role  # type: ignore
    )

    return {
        "message": f"Welcome back {user.username}",
        "access_token": token,
        "token_type": "bearer"
    }


@router.get("/private-key/decrypt")
def private_key_decryption(
    private_key_request: DecryptPrivateKeySchema,
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):
    user = search_for_user_username(current_user["username"], db)
    if not user:
        raise HTTPException(detail=USER_DOES_NOT_EXIST, status_code=422)

    password_verify = compare_user_password(
        user.auth_salt,  # type: ignore
        private_key_request.password,
        user.hashed_password  # type: ignore
    )

    if not password_verify:
        raise HTTPException(detail="Incorrect password", status_code=401)

    kek = PBKDF2(
        private_key_request.password,
        user.crypto_salt,  # type: ignore
        dkLen=32,
        count=300_000
    )
    cipher = AES.new(
        kek,
        AES.MODE_EAX,
        nonce=user.private_key_nonce  # type: ignore
    )  # type: ignore
    private_key = cipher.decrypt_and_verify(
        user.encrypted_private_key,
        user.private_key_tag
    )

    return {"private_key": private_key[:50].hex()+"..."}


@router.post("/password/change")
def change_password(
    change_password_request: ChangePasswordSchema, current_user=Depends(get_current_user),
    db=Depends(get_db)
):
    user = search_for_user_username(current_user["username"], db)
    if not user:
        raise HTTPException(detail=USER_DOES_NOT_EXIST, status_code=422)

    password_verify = compare_user_password(
        user.auth_salt,  # type: ignore
        change_password_request.old_password,
        user.hashed_password  # type: ignore
    )

    if not password_verify:
        raise HTTPException(detail="Incorrect old password", status_code=401)

    old_kek = PBKDF2(
        change_password_request.old_password,
        user.crypto_salt,  # type: ignore
        dkLen=32,
        count=300_000
    )

    cipher = AES.new(
        old_kek,
        AES.MODE_EAX,
        nonce=user.private_key_nonce  # type: ignore
    )  # type: ignore

    private_key = cipher.decrypt_and_verify(
        user.encrypted_private_key,
        user.private_key_tag,
    )

    new_auth_salt = get_random_bytes(16)
    new_crypto_salt = get_random_bytes(16)

    new_password_hash = password_hash(
        change_password_request.new_password,
        new_auth_salt
    )

    new_kek = PBKDF2(
        change_password_request.new_password,
        new_crypto_salt,
        dkLen=32,
        count=300_000
    )

    cipher = AES.new(new_kek, AES.MODE_EAX)
    new_encrypted_private_key, new_tag = cipher.encrypt_and_digest(private_key)

    change_password_crud(
        user=user,
        new_auth_salt=new_auth_salt, new_crypto_salt=new_crypto_salt, new_password_hash=new_password_hash, new_encrypted_private_key=new_encrypted_private_key,
        new_private_key_nonce=cipher.nonce,
        new_tag=new_tag,
        db=db
    )

    return {"message": "Password changed successfully"}
