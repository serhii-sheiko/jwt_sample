from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

SECRET_KEY = "super-secret-key-change-me-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


fake_users_db: dict[str, dict] = {}

app = FastAPI(title="JWT Auth Demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UserCreate(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    username: str
    registered_at: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(data: dict, expires_delta: timedelta) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + expires_delta
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_token_pair(username: str) -> TokenPair:
    access = create_token(
        data={"sub": username, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh = create_token(
        data={"sub": username, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    return TokenPair(access_token=access, refresh_token=refresh)



async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
) -> dict:
    """
    FastAPI calls this automatically for any endpoint
    that declares `Depends(get_current_user)`.

    Flow:
      1. oauth2_scheme extracts the Bearer token from header
      2. We decode & validate the JWT
      3. We look up the user in the DB
      4. Return user dict (or raise 401)
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        token_type: str | None = payload.get("type")

        if username is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception

    return user


@app.post("/auth/register", response_model=UserOut, status_code=201)
async def register(body: UserCreate):
    if body.username in fake_users_db:
        raise HTTPException(status_code=409, detail="Username already taken")

    fake_users_db[body.username] = {
        "username": body.username,
        "hashed_password": hash_password(body.password),
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    return fake_users_db[body.username]


@app.post("/auth/login", response_model=TokenPair)
async def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = fake_users_db.get(form.username)

    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return create_token_pair(form.username)


@app.post("/auth/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest):
    try:
        payload = jwt.decode(body.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        token_type: str | None = payload.get("type")

        if username is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if username not in fake_users_db:
        raise HTTPException(status_code=401, detail="User not found")

    return create_token_pair(username)


@app.get("/users/me")
async def read_current_user(
    current_user: Annotated[dict, Depends(get_current_user)],
):
    return {
        "username": current_user["username"],
        "registered_at": current_user["registered_at"],
        "message": "You have access to the protected resource! 🔐",
    }
