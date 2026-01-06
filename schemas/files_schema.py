from datetime import datetime
from fastapi import UploadFile
from pydantic import BaseModel


class FileDecryptSchema(BaseModel):
    file_id: str
    password: str


class FileGetResponseSchema(BaseModel):
    id: str
    filename: str | None
    content_type: str | None
    last_decrypted_at: datetime | None

    class Config:
        from_attributes = True
