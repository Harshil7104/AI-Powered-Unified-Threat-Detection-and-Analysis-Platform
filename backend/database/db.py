import os
# pyrefly: ignore [missing-import]
from sqlalchemy import create_engine
# pyrefly: ignore [missing-import]
from sqlalchemy.ext.declarative import declarative_base
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import sessionmaker
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
from pathlib import Path

# Load env variables using path relative to backend directory
env_path = Path(__file__).resolve().parent.parent / ".env"
# pyrefly: ignore [missing-import]
load_dotenv(dotenv_path=env_path)

db_host = os.getenv("DB_HOST", "localhost")
db_port = os.getenv("DB_PORT", "3306")
db_user = os.getenv("DB_USER", "root")
db_pass = os.getenv("DB_PASSWORD", "")
db_name = os.getenv("DB_NAME", "cyber_platform")

# Try to connect to MySQL database
MYSQL_URL = f"mysql+pymysql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
SQLITE_URL = "sqlite:///./cyber_platform.db"

try:
    # Use 3 seconds connection timeout so it doesn't hang startup
    engine = create_engine(
        MYSQL_URL, 
        connect_args={"connect_timeout": 3}
    )
    # Test connection
    with engine.connect() as conn:
        print("Connected to MySQL database successfully.")
except Exception as e:
    print(f"MySQL connection failed: {e}. Falling back to SQLite database.")
    engine = create_engine(
        SQLITE_URL, 
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# DB dependency to yield session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
