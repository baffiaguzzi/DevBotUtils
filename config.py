BOT_TOKEN = "7502880630:AAExhQlTZdb-GhGtQ5wy-ybWQV8CJw99O_E"
BUGS_FILE = "bugs.json"
BUG_DIR = "bug_reports"
ALLOWED_USERS = [123456789, 6719207577]

def is_authorized(user_id: int) -> bool:
    return user_id in ALLOWED_USERS
