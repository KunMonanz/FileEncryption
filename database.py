from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import Engine

DATABASE_URL = "sqlite:///./file_encrypt.db"

engine = create_engine(DATABASE_URL, echo=True)

Base = declarative_base()
session = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()
