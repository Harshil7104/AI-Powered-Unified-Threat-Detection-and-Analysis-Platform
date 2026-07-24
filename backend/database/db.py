from sqlalchemy import create_engine

DATABASE_URL = "mysql+pymysql://root:password@localhost/cyber_platform"

engine = create_engine(DATABASE_URL)