from fastapi import APIRouter, Depends

from auth import get_admin_user
from crud.file_crud import get_total_storage
from crud.users_crud import get_all_users, get_number_of_users_crud
from database import get_db
from utils import human_readable_size

router = APIRouter(prefix="/api/v1/admin")


@router.get("/users")
def get_users(
    admin_user=Depends(get_admin_user),
    db=Depends(get_db)
):
    users = get_all_users(db)
    return {"users": [user.username for user in users]}


@router.get("/user-number")
def get_number_of_users(
    admin_user=Depends(get_admin_user),
    db=Depends(get_db)
):
    return get_number_of_users_crud(db)


@router.get("/total-storage-used")
def get_storage(
    admin_user=Depends(get_admin_user),
    db=Depends(get_db)
):
    total_storage_size = get_total_storage(db)

    return {
        "total storage size used": human_readable_size(total_storage_size)
    }
