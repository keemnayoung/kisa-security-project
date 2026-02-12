import os
from dotenv import load_dotenv

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'database': os.getenv('DB_NAME', 'kisa_db'),
    'user': os.getenv('DB_USER', 'kisa_app'),
    'password': os.getenv('DB_PASS', ''),
    'charset': 'utf8mb4'
}
