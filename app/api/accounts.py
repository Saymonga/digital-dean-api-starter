"""Student task: register these four functions on the SAME existing app."""
from typing import Annotated
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Path, Response

from app.api.account_validation import SensitiveRoute
from app.db.connection import DB_PATH
from app.repositories.user_repository import (
    UserConflict, UserNotFound, UserReferenced, UserRepository,
)
from app.schemas.user_account import LoginRequest, UserCreate, UserPublic

router = APIRouter(tags=["accounts"], route_class=SensitiveRoute)


def get_user_repository() -> UserRepository:
    return UserRepository(DB_PATH)


Repository = Annotated[UserRepository, Depends(get_user_repository)]
UserId = Annotated[int, Path(gt=0, le=9_223_372_036_854_775_807)]


# TODO: add decorators with the agreed paths, status codes and response models.
# TODO: UserConflict -> safe 409, UserNotFound -> safe 404,
# UserReferenced -> safe 409, sqlite3.Error -> safe 500.
# Never include exception text, SQL, path, request body, hash or salt in errors.
# Route validation redaction is already provided by SensitiveRoute.

def register_user(data: UserCreate, repository: Repository) -> UserPublic:
    raise NotImplementedError("TODO: POST /api/v1/users -> 201")


def delete_user(user_id: UserId, repository: Repository) -> Response:
    raise NotImplementedError("TODO: DELETE /api/v1/users/{user_id} -> empty 204")


def block_user(user_id: UserId, repository: Repository) -> UserPublic:
    raise NotImplementedError("TODO: PATCH /api/v1/users/{user_id}/block -> 200")


def login(data: LoginRequest, repository: Repository) -> bool:
    raise NotImplementedError("TODO: POST /api/v1/auth/login -> JSON boolean")
