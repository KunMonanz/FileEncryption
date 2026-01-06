import uuid
from models.user_model import User
from sqlalchemy.orm import Session
from encryption import verify_password, password_hash
from sqlalchemy import select


def create_user(
    username: str,
    hashed_password: bytes,
    auth_salt: bytes,
    crypto_salt: bytes,
    encrypted_private_key: bytes,
    private_key_tag: bytes,
    public_key: bytes,
    private_key_nonce: bytes,
    db: Session
):
    try:
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=hashed_password,
            auth_salt=auth_salt,
            crypto_salt=crypto_salt,
            encrypted_private_key=encrypted_private_key,
            private_key_tag=private_key_tag,
            public_key=public_key,
            private_key_nonce=private_key_nonce
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    except Exception as e:
        db.rollback()
        raise e


def search_for_user_username(
    username: str,
    db: Session
) -> User | None:
    try:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            return None
        return user
    except Exception as e:
        print(f"Exception: {e}")
        return None


def get_user_id(db: Session, username: str) -> str | None:
    try:
        user_id = db.query(User).filter_by(username=username).first()
        if not user_id:
            return None
        return user_id.id  # type: ignore
    except Exception as e:
        print(f"Exception: {e}")
        return None


def compare_user_password(auth_salt: bytes, plain_password: str, hashed_password: bytes) -> bool:
    correct_password = verify_password(
        plain_password,
        hashed_password,  # type: ignore
        auth_salt  # type: ignore
    )
    if correct_password:
        return True
    return False


def change_password_crud(
    user: User,
    new_auth_salt: bytes,
    new_crypto_salt: bytes,
    new_password_hash: bytes,
    new_encrypted_private_key: bytes,
    new_private_key_nonce: bytes,
    new_tag: bytes,
    db
):
    try:
        user.hashed_password = new_password_hash  # type: ignore
        user.auth_salt = new_auth_salt  # type: ignore
        user.crypto_salt = new_crypto_salt  # type: ignore
        user.encrypted_private_key = new_encrypted_private_key  # type: ignore
        user.private_key_nonce = new_private_key_nonce  # type: ignore
        user.private_key_tag = new_tag  # type: ignore
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Exception: {e}")
