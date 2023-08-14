import asyncio
from typing import Union, List

from fastapi import HTTPException
from auth_utils import AuthJwtCsrf
from bson import ObjectId
from decouple import config
import motor.motor_asyncio
from schemas import Todo, TodoBody, UserInfo, UserBody

MONGO_API_KEY = config("MONGO_API_KEY")

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
client.get_io_loop = asyncio.get_event_loop
database = client.todo_db
collection_todo = database.todo
collection_user = database.user
auth = AuthJwtCsrf()


def todo_serializer(todo: dict) -> Todo:
    """This is a serializer from MongoDB data types

    Args:
        todo (dict): {"_id": ObjectId(number), "title": str, "description": str}

    Returns:
        Todo: {"id": str, "title": str, "description": str}
    """
    return {
        "id": str(todo["_id"]),
        "title": todo["title"],
        "description": todo["description"]
    }

def user_serializer(user: dict) -> UserInfo:
    return {
        "id": str(user["_id"]),
        "email": user["email"]
    }

async def db_create_todo(data: TodoBody) -> Union[Todo, bool]:
    """This is a function for create single task

    Args:
        data (TodoBody): {"title": str, "description": str}

    Returns:
        Union[Todo, bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> False
    """
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})
    if new_todo:
        return todo_serializer(new_todo)
    return False

async def db_find_todo_all() -> Union[List[Todo], bool]:
    """This is a function for get all todo data

    Returns:
        Union[List[Todo], bool]: Success -> [ ... , {"id": str, "title": str, "description": str}], Failed -> False
    """
    todo_list = await collection_todo.find().to_list(length=100)
    if todo_list:
        return map(todo_serializer, todo_list)
    return False

async def db_find_todo_by_id(id: str) -> Union[Todo, bool]:
    """This is a function for get single todo data by id

    Args:
        id (str): ID of the task you would like to find

    Returns:
        Union[Todo, bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> False
    """
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        return todo_serializer(todo)
    return False

async def db_update_todo(id: str, data: TodoBody) -> Union[Todo, bool]:
    """This is a function for update single todo data

    Args:
        id (str): Task ID
        data (TodoBody): {"title": str, "description": str}

    Returns:
        Union[Todo, bool]: Success -> {"id": str, "title": str, "description": str}, Failed -> False
    """
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if not todo:
        return False
    update_todo = await collection_todo.update_one({"_id": ObjectId(id)}, {"$set": data})
    if (update_todo.modified_count > 0):
        new_todo = await collection_todo.find_one({"_id": ObjectId(id)})
        return todo_serializer(new_todo)
    
async def db_delete_todo(id: str) -> bool:
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if not todo:
        return False
    delete_todo = await collection_todo.delete_one({"_id": ObjectId(id)})
    if (delete_todo.deleted_count > 0):
        return True
    
async def db_signup(data: UserBody) -> UserInfo:
    email = data.get("email")
    password = data.get("password")
    overlap_user = await collection_user.find_one({"email": email})
    if overlap_user:
        raise HTTPException(status_code=400, detail="Email is already taken")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")
    user = await collection_user.insert_one({"email": email, "password": auth.generate_hashed_pw(password)})
    new_user = await collection_user.find_one({"_id": user.inserted_id})
    return user_serializer(new_user)

async def db_login(data: UserBody) -> str:
    email = data.get("email")
    password = data.get("password")
    user = await collection_user.find_one({"email": email})
    if not user or not auth.verify_pw(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = auth.encode_jwt(user["email"])
    return token