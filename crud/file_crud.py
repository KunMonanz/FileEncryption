from sqlalchemy.orm import Session

from models.file_model import File


def upload_file_crud(
    filename: str | None,
    encrypted_aes_key: bytes,
    aes_nonce: bytes,
    tag: bytes,
    ciphertext: bytes,
    owner_id: str,
    db: Session,
    content_type: str | None = None
):
    try:
        file = File(
            filename=filename,
            content=ciphertext,
            encrypted_aes_key=encrypted_aes_key,
            nonce=aes_nonce,
            tag=tag,
            owner_id=owner_id,
            content_type=content_type
        )
        db.add(file)
        db.commit()
        db.refresh(file)
        return file
    except Exception as e:
        db.rollback()
        print(f"Exception: {e}")


def get_file_by_id(file_id: str, db: Session) -> File | None:
    file = db.query(File).filter_by(id=file_id).first()
    if not file:
        return None
    return file


def get_files_by_owner_id(owner_id: str, db: Session) -> list[File]:
    files = db.query(File).filter_by(owner_id=owner_id).all()
    return files
