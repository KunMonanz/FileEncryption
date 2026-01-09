from sqlalchemy import (
    Column,
    Integer,
    String,
    LargeBinary,
    CheckConstraint,
    DateTime,
    func,
    ForeignKey
)
from sqlalchemy.orm import relationship
from database import Base
import uuid


class File(Base):
    __tablename__ = "files"

    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True
    )
    filename = Column(
        String,
        CheckConstraint("length(filename) <= 255",
                        name="filename_length_check"),
        index=True,
    )
    content = Column(
        LargeBinary,
        CheckConstraint("length(content)<=5242880", name="content_size_check"),
        nullable=False
    )
    content_type = Column(String)
    size = Column(Integer, nullable=False)
    nonce = Column(LargeBinary, nullable=False)
    tag = Column(LargeBinary, nullable=False)
    encrypted_aes_key = Column(LargeBinary, nullable=False)
    uploaded_at = Column(DateTime, server_default=func.now())
    last_decrypted_at = Column(DateTime)
    owner_id = Column(
        String,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    owner = relationship("User", back_populates="files", lazy="joined")
