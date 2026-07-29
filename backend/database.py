from sqlalchemy import create_engine, text

DB_USER = "postgres"
DB_PASSWORD = "milimillion"  # apna password
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "phishing_db"

DATABASE_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)

def get_connection():
    return engine.connect()