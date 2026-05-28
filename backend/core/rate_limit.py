from slowapi import Limiter
from slowapi.util import get_remote_address

# Singleton shared by main.py (registration) and route handlers (decoration).
limiter = Limiter(key_func=get_remote_address)
