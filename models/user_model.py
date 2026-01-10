from sqlalchemy import (
    Column,
    String,
    DateTime,
    func,
    LargeBinary,
    CheckConstraint
)
from sqlalchemy.orm import relationship
from database import Base
import uuid


class User(Base):
    __tablename__ = "users"
    id = Column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True
    )
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    auth_salt = Column(LargeBinary)
    role = Column(
        String,
        CheckConstraint(
            "role in ('admin', 'user')",
            name="role_check"
        ),
        default="user"
    )
    crypto_salt = Column(LargeBinary, nullable=False)
    encrypted_private_key = Column(LargeBinary, nullable=False)
    private_key_nonce = Column(LargeBinary, nullable=False)
    private_key_tag = Column(LargeBinary, nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    last_login = Column(DateTime, server_default=func.now())
    files = relationship(
        "File", back_populates="owner",
        cascade="all, delete-orphan",
        lazy="joined"
    )
