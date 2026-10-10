import jinja2
from fastapi import APIRouter

router = APIRouter()


def render(q):
    return jinja2.Template(q).render()


@router.get('/{item_id}')
def read_item(item_id: int, q: str = None):
    return {'item': item_id, 'html': render(q)}
