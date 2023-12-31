from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Path,Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette import status
from models import Todos
from database import SessionLocal
from .auth import get_current_user
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


router = APIRouter()

templates = Jinja2Templates(directory="templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class TodoRequest(BaseModel):
    title: str = Field(min_length=3)
    description: str = Field(min_length=3, max_length=100)
    priority: int = Field(gt=0, lt=6)
    complete: bool


@router.get("/test")
async def test(request: Request):
    #return templates.TemplateResponse("home.html", {"request": request})
    #return templates.TemplateResponse("add-todo.html", {"request": request})
    #return templates.TemplateResponse("edit-todo.html", {"request": request})
    #return templates.TemplateResponse("login.html", {"request": request})
    return templates.TemplateResponse("register.html", {"request": request})


@router.get("/", status_code=status.HTTP_200_OK)
async def read_all(user: user_dependency, db: db_dependency):
    # return db.query(Todos).all()
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    return db.query(Todos).filter(Todos.owner_id == user.get('id')).all()


@router.get("/todo/{todo_id}", status_code=status.HTTP_200_OK)
async def read_todo(user: user_dependency, db: db_dependency,
                    todo_id: int = Path(gt=0)):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')

    # todo_model = db.query(Todos).filter(Todos.id == todo_id).first()
    #We are also filtering owner id is same as the user logged in
    todo_model = db.query(Todos).filter(Todos.id == todo_id) \
        .filter(Todos.owner_id == user.get('id')).first()

    if todo_model is not None:
        return todo_model
    raise HTTPException(status_code=404, detail='Todo not found')


@router.post("/todo", status_code=status.HTTP_201_CREATED)
# user will have the return value of get_current_user function
async def create_todo(user: user_dependency, db: db_dependency,
                      todo_request: TodoRequest):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')

    # as we added owner_id as a foreign key in todos table,we are assigning that value
    todo_model = Todos(**todo_request.dict(), owner_id=user.get('id'))
    db.add(todo_model)
    db.commit()


@router.put("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def update_todo(user: user_dependency,db: db_dependency,
                      todo_request: TodoRequest, todo_id: int = Path(gt=0)):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')

    #todo_model = db.query(Todos).filter(Todos.id == todo_id).first()
    todo_model = db.query(Todos).filter(Todos.id == todo_id)\
        .filter(Todos.owner_id == user.get('id')).first()
    if todo_model is None:
        raise HTTPException(status_code=404, detail='Todo not found')

    todo_model.title = todo_request.title
    todo_model.description = todo_request.description
    todo_model.priority = todo_request.priority
    todo_model.complete = todo_request.complete
    db.add(todo_model)
    db.commit()


@router.delete("/todo/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_todo(user: user_dependency,db: db_dependency,
                      todo_id: int = Path(gt=0)):

    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    #todo_model = db.query(Todos).filter(Todos.id == todo_id).first()
    todo_model = db.query(Todos).filter(Todos.id == todo_id)\
        .filter(Todos.owner_id == user.get('id')).first()

    if todo_model is None:
        raise HTTPException(status_code=404, detail='Todo not found')

    db.query(Todos).filter(Todos.id == todo_id)\
        .filter(Todos.owner_id == user.get('id')).delete()
    db.commit()
