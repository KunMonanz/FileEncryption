from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File as FastAPIFile
)
from fastapi.responses import StreamingResponse

from io import BytesIO

from crud.file_crud import upload_file_crud
from crud.file_crud import get_file_by_id, upload_file_crud, get_files_by_owner_id
from crud.users_crud import compare_user_password, search_for_user_username

from sqlalchemy.orm import Session

from auth import get_current_user

from database import get_db

from schemas.files_schema import (
    FileDecryptSchema,
    FileDecryptSchema,
    FileGetResponseSchema
)

router = APIRouter(prefix="/api/v1/files")


@router.get("/", response_model=list[FileGetResponseSchema])
def get_files(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves all files belonging to the current user.
    """

    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    current_user = search_for_user_username(
        current_user[0],
        db
    )

    return get_files_by_owner_id(current_user.id, db)  # type: ignore


@router.post("/upload")
def upload_file(
    file: UploadFile = FastAPIFile(...),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Uploads a file:
    - Encrypts the file with a random AES key (DEK)
    - Encrypts the AES key with the user's RSA public key
    - Stores encrypted file, AES key, nonce, tag, and metadata in DB
    """

    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    current_user = search_for_user_username(
        current_user["username"],
        db
    )

    file_bytes = file.file.read()
    filename = file.filename
    content_type = file.content_type

    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_bytes)

    public_key = RSA.import_key(current_user.public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    file = upload_file_crud(
        filename=filename,
        content_type=content_type,
        encrypted_aes_key=encrypted_aes_key,
        aes_nonce=cipher_aes.nonce,
        tag=tag,
        ciphertext=ciphertext,
        owner_id=current_user.id,
        db=db
    )

    if not file:
        raise HTTPException(
            detail="File upload failed",
            status_code=500
        )

    return {
        "file_id": str(file.id),
        "filename": filename,
        "message": "File uploaded and encrypted successfully"
    }


@router.get("/decrypt/")
def decrypt_file(
    file_decrypt_request: FileDecryptSchema,
    current_user=Depends(get_current_user),
    db=Depends(get_db)
):

    current_user = search_for_user_username(
        current_user["username"],
        db
    )

    file = get_file_by_id(file_decrypt_request.file_id, db)

    if not file:
        raise HTTPException(
            detail="File does not exist",
            status_code=404
        )

    if file.owner_id != current_user.id:  # type: ignore
        raise HTTPException(
            status_code=403,
            detail="Not your file"
        )

    user = current_user

    password_verify = compare_user_password(
        user.auth_salt,
        file_decrypt_request.password,
        user.hashed_password  # type: ignore
    )

    if not password_verify:
        raise HTTPException(
            detail="Incorrect password",
            status_code=401
        )

    kek = PBKDF2(
        file_decrypt_request.password,
        user.crypto_salt,  # type: ignore
        dkLen=32,
        count=300_000
    )
    cipher_priv = AES.new(
        kek,
        AES.MODE_EAX,
        nonce=user.private_key_nonce  # type: ignore
    )  # type: ignore
    private_key = cipher_priv.decrypt_and_verify(
        user.encrypted_private_key,
        user.private_key_tag
    )

    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(file.encrypted_aes_key)  # type: ignore

    cipher_aes = AES.new(
        aes_key,
        AES.MODE_EAX,
        nonce=file.nonce  # type: ignore
    )  # type: ignore
    plaintext = cipher_aes.decrypt_and_verify(
        file.content,
        file.tag
    )

    return StreamingResponse(
        BytesIO(plaintext),
        media_type=file.content_type,  # type: ignore
        headers={
            "Content-Disposition": f'attachment; filename="{file.filename}"'
        }
    )
