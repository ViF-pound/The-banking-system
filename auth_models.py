from sqlalchemy import ForeignKey
from db_users import Base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import text
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from account_model import account

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    password: Mapped[bytes]
    name: Mapped[str]
    surname: Mapped[str]
    phone: Mapped[str]


    is_user: Mapped[bool] = mapped_column(default=True, server_default=text('true'), nullable=False)
    is_admin: Mapped[bool] = mapped_column(default=False, server_default=text('false'), nullable=False)
# one to many счета
    users: Mapped[list["Account"]] = relationship(uselist=True, back_populates="owner")

    
    def __init__(self, email, password, name, surname,  phone):
        self.email = email
        self.password = password
        self.name = name
        self.surname = surname
        self.phone = phone

      