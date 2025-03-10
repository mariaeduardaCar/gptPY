import os
from dotenv import load_dotenv
load_dotenv()  # Carrega variáveis do .env


SECRET_KEY = "12345"

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")


