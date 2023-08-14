from typing import List, Union
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from auth_utils import AuthJwtCsrf
from database import db_create_todo, db_find_todo_all, db_find_todo_by_id, db_update_todo, db_delete_todo
from fastapi_csrf_protect import CsrfProtect
from schemas import Todo, TodoBody, SuccessMsg
from starlette.status import HTTP_201_CREATED

router = APIRouter()
auth = AuthJwtCsrf()

@router.post("/api/todo", response_model=Todo)
async def create_todo(request: Request, response: Response, data: TodoBody, csrf_protect: CsrfProtect = Depends()) -> Union[Todo, bool]:
    """This is a endpoint to create a new Todo.
    - JWT(httpOnly)
    - Refresh JWT
    - CSRF token

    Args:
        request (Request): request object
        response (Response): response object
        data (TodoBody): {"title": str, "description": str}
        csrf_protect (CsrfProtect): CSRF protection

    Raises:
        HTTPException: Failed -> 404 Error if the response object does not exist.

    Returns:
        Union[Todo, bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> Fales
    """
    new_token = auth.verify_csrf_update_jwt(request, csrf_protect)
    todo = jsonable_encoder(data)
    res = await db_create_todo(todo)
    response.status_code = HTTP_201_CREATED
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    if res:
        return res
    raise HTTPException(status_code=404, detail="Failed to create task")

@router.get("/api/todo", response_model=List[Todo])
async def get_todo(request: Request) -> Union[List[Todo], bool]:
    """This is a endpoint to get all todo data.
    - JWT(httpOnly)

    Args:
        request (Request): request object

    Raises:
        HTTPException: Failed -> 404 Error if the response object does not exist.

    Returns:
        Union[List[Todo], bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> Fales
    """
    auth.verify_jwt(request)
    res = await db_find_todo_all()
    if res:
        return res
    raise HTTPException(status_code=404, detail="Task does not exist")

@router.get("/api/todo/{id}", response_model=Todo)
async def get_single_todo(request: Request, response: Response, id: str) -> Union[Todo, bool]:
    """This is a endpoint to get single todo data.
    - JWT(httpOnly)
    - Refresh JWT

    Args:
        request (Request): request object
        response (Response): response object
        id (str): Task ID

    Raises:
        HTTPException: Failed -> 404 Error if the response object does not exist.

    Returns:
        Union[Todo, bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> Fales
    """
    new_token, _ = auth.verify_update_jwt(request)
    res = await db_find_todo_by_id(id)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    if res:
        return res
    raise HTTPException(status_code=404, detail="Task ID: {id} does not exist")

@router.put("/api/todo/{id}", response_model=Todo)
async def update_todo(request: Request, response: Response, id: str, data: TodoBody, csrf_protect: CsrfProtect = Depends()) -> Union[Todo, bool]:
    """This is a endpoint to update single todo.
    - JWT(httpOnly)
    - Refresh JWT
    - CSRF token

    Args:
        request (Request): request object
        response (Response): response object
        id (str): Task ID
        data (TodoBody): {"title": str, "desciption": str}
        csrf_protect (CsrfProtect): CSRF protection

    Raises:
        HTTPException: Failed -> 404 Error if the response object does not exist.

    Returns:
        Union[Todo, bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> Fales
    """
    new_token = auth.verify_csrf_update_jwt(request)
    todo = jsonable_encoder(data)
    res = await db_update_todo(id, todo)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    if res:
        return res
    raise HTTPException(status_code=404, detail="Failed to update task")

@router.delete("/api/todo/{id}", response_model=SuccessMsg)
async def delete_todo(request: Request, response: Response, id: str, csrf_protect: CsrfProtect = Depends()) -> SuccessMsg:
    """This is a endpoint to delete single todo.
    - JWT(httpOnly)
    - Refresh JWT
    - CSRF token

    Args:
        request (Request): request object
        response (Response): response object
        id (str): Task ID
        csrf_protect (CsrfProtect): CSRF protection

    Raises:
        HTTPException: Failed -> 404 Error if the response object does not exist.

    Returns:
        SuccessMsg: {"message": str}
    """
    new_token = auth.verify_csrf_update_jwt(request)
    res = await db_delete_todo(id)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    if res:
        return {"message": "Deletion of the task is completed"}
    raise HTTPException(status_code=404, detail="Failed to delete task")