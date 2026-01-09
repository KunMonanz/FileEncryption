from fastapi import File, HTTPException, UploadFile
from dataclasses import dataclass

MAX_SIZE = 5 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


@dataclass
class UploadedFileData:
    filename: str | None
    content_type: str | None
    size: int
    data: bytes


async def read_validate_file(file: UploadFile = File(...)) -> UploadedFileData | None:
    size = 0
    chunks: list[bytes] = []

    while chunk := await file.read(CHUNK_SIZE):
        size += len(chunk)
        if size > MAX_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File is too large, should not be more than 5MB"
            )
        chunks.append(chunk)

    return UploadedFileData(
        filename=file.filename,
        content_type=file.content_type,
        size=size,
        data=b"".join(chunks)
    )


def human_readable_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    else:
        return f"{size / (1024 * 1024):.2f} MB"
