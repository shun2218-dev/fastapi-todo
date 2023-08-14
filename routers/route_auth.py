from fastapi import APIRouter, Depends, Request, Response
from fastapi.encoders import jsonable_encoder
from auth_utils import AuthJwtCsrf
from database import db_login, db_signup
from fastapi_csrf_protect import CsrfProtect
from schemas import Csrf, UserInfo, UserBody, SuccessMsg


router = APIRouter()
auth = AuthJwtCsrf()

@router.get("/api/csrftoken", response_model=Csrf)
async def get_csrf_token(response: Response, csrf_protect: CsrfProtect = Depends()) -> Csrf:
    """This is a endpoint to get the CSRF token

    Args:
        response (Response): FastAPI response object
        csrf_protect (CsrfProtect, optional): CSRF protection. Defaults to Depends().

    Returns:
        Csrf: CSRF token
    """
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    res = {"csrf_token": csrf_token}
    csrf_protect.set_csrf_cookie(signed_token, response)
    return res

@router.post("/api/register", response_model=UserInfo)
async def signup(request: Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()) -> UserInfo:
    """This is a endpoint to sign up
    - CSRF token

    Args:
        request (Request): FastAPI request object
        response (Response): FastAPI response object
        user (UserBody): Email and password
        csrf_protect (CsrfProtect, optional): CSRF protection. Defaults to Depends().

    Returns:
        UserInfo: New user info
    """
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(user)
    new_user = await db_signup(user)
    csrf_protect.unset_csrf_cookie(response)
    return new_user

@router.post("/api/login", response_model=SuccessMsg)
async def login(request: Request, response: Response, user: UserBody, csrf_protect: CsrfProtect = Depends()) -> SuccessMsg:
    """This is a endpoint to log in
    - CSRF token

    Args:
        request (Request): FastAPI request object
        response (Response): FastAPI response object
        user (UserBody): Email and password
        csrf_protect (CsrfProtect, optional): CSRF protect. Defaults to Depends().

    Returns:
        SuccessMsg: Return message when login was successful
    """
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    user = jsonable_encoder(user)
    token = await db_login(user)
    csrf_protect.unset_csrf_cookie(response)
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, samesite="none", secure=True)
    return {"message": "Successfully logged-in"}

@router.post("/api/logout", response_model=SuccessMsg)
def logout(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()) -> SuccessMsg:
    """This is a endpoint to log out
    - CSRF token

    Args:
        request (Request): FastAPI request object
        response (Response): FastAPI response object
        csrf_protect (CsrfProtect, optional): CSRF protect. Defaults to Depends().

    Returns:
        SuccessMsg: Rturn message when logout was successful
    """
    csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
    csrf_protect.validate_csrf(csrf_token)
    csrf_protect.unset_csrf_cookie(response)
    response.set_cookie(key="access_token", value=f"", httponly=True, samesite="none", secure=True)
    return {"message": "Successfully logged-out"}

@router.get("/api/user", response_model=UserInfo)
def get_user_refresh_jwt(request: Request, response: Response) -> UserInfo:
    """This is a endpoint to get user information and refresh JWT token

    Args:
        request (Request): FastAPI request object
        response (Response): FastAPI response object

    Returns:
        UserInfo: User information of logged in
    """
    new_token, subject = auth.verify_update_jwt(request)
    response.set_cookie(key="access_token", value=f"Bearer {new_token}", httponly=True, samesite="none", secure=True)
    return {"email": subject}