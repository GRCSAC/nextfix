import yaml
from fastapi import APIRouter, Depends

from app.api.deps import get_current_user

router = APIRouter(prefix='/users', dependencies=[Depends(get_current_user)])


@router.get('/')
def list_users():
    return []


@router.post('/import')
def import_users(body: str):
    return yaml.load(body)
