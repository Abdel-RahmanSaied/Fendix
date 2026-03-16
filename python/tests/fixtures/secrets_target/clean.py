# This file contains no secrets — everything comes from environment variables
import os

API_KEY = os.environ["API_KEY"]
DB_URL = os.environ["DATABASE_URL"]
SECRET = os.getenv("SECRET_KEY", "")


def get_client():
    """Return an API client configured from environment."""
    return {"key": API_KEY, "db": DB_URL}
