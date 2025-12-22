import os

BOT_TOKEN = os.getenv("BOT_TOKEN")

BUGS_FILE = os.getenv("BUGS_FILE", "bugs.json")
BUG_DIR = os.getenv("BUG_DIR", "bug_reports")

ALLOWED_USERS = list(map(int, filter(None, os.getenv("ALLOWED_USERS", "").split(","))))

def is_authorized(user_id: int) -> bool:
    """Verify if the user is allowed"""
    return user_id in ALLOWED_USERS