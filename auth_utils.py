from datetime import datetime, timedelta

from fastapi import HTTPException, Request
from decouple import config
from passlib.context import CryptContext
from fastapi_csrf_protect import CsrfProtect

import jwt

JWT_KEY = config("JWT_KEY")


class AuthJwtCsrf():
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    def generate_hashed_pw(self, password: str) -> str:
        return self.pwd_ctx.hash(password)
    
    def verify_pw(self, plain_pw: str, hashed_pw: str) -> bool:
        return self.pwd_ctx.verify(plain_pw, hashed_pw)
    
    def encode_jwt(self, email: str) -> str:
        payload = {
            "exp": datetime.utcnow() + timedelta(days=0, minutes=5),
            "iat": datetime.utcnow(),
            "sub": email
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")
    
    def decode_jwt(self, token: str) -> str:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="The JWT has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="JWT is not valid")
        
    def verify_jwt(self, request: Request) -> str:
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(status_code=401, detail="JWT doesn't exist: may not set yet or deleted")
        _, _, value = token.partition(" ")
        subject = self.decode_jwt(value)
        return subject
    
    def verify_update_jwt(self, request: Request) -> tuple[str, str]:
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token, subject
    
    def verify_csrf_update_jwt(self, request: Request, csrf_protect: CsrfProtect) -> str:
        csrf_token = csrf_protect.get_csrf_from_headers(request.headers)
        csrf_protect.validate_csrf(csrf_token)
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token