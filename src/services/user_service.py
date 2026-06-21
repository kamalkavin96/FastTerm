from fastapi import HTTPException
from core.constants import USERNAME_RE
from repositories.user_repository import (
    get_user_row,
    create_user,
    delete_user,
    list_users,
    update_password,
    count_users,
    count_totp_users,
)
from utils.password import hash_password, verify_password
import sqlite3


def get_me(username: str) -> dict:
    row = get_user_row(username)
    return {
        "username": username,
        "has_totp": bool(row["totp_secret"]) if row else False,
    }


def change_password(username: str, current_password: str, new_password: str):
    row = get_user_row(username)
    if not row or not verify_password(current_password, row["pw_hash"], row["pw_salt"]):
        raise HTTPException(400, "Current password is incorrect")
    if len(new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    h, s = hash_password(new_password)
    update_password(username, h, s)


def admin_create_user(username: str, password: str, is_admin: bool):
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "Invalid username")
    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    try:
        create_user(username, password, is_admin)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists")


def admin_delete_user(username: str, requesting_admin: str):
    if username == requesting_admin:
        raise HTTPException(400, "Cannot delete your own account")
    delete_user(username)


def admin_list_users():
    return list_users()