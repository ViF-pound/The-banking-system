from sqlalchemy import create_engine
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///users.db")

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id:Mapped[int] = mapped_column(primary_key=True)
    name:Mapped[str]
    surname:Mapped[str]
    email:Mapped[str]
    number:Mapped[str]
    password:Mapped[str]

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()
