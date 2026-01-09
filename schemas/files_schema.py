from datetime import datetime
from fastapi import UploadFile
from pydantic import BaseModel


class FileDecryptSchema(BaseModel):
    password: str


class FileGetResponseSchema(BaseModel):
    id: str
    filename: str | None
    content_type: str | None
    size: str
    last_decrypted_at: datetime | None

    class Config:
        from_attributes = True

    @classmethod
    def from_bytes(cls, filename: str | None, content_type: str | None, size_bytes: int, id: str, last_decrypted_at: datetime | None):
        from utils import human_readable_size
        return cls(
            id=id,
            filename=filename,
            content_type=content_type,
            size=human_readable_size(size_bytes),
            last_decrypted_at=last_decrypted_at
        )
