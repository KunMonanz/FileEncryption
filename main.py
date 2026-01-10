from fastapi import FastAPI

from routers import admin_routers
import routers.file_routers as file_routers
import routers.user_routers as user_routers

from database import engine, Base

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(file_routers.router)
app.include_router(user_routers.router)
app.include_router(admin_routers.router)
