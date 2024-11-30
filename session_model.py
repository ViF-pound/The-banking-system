from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import TYPE_CHECKING
from db_users import session, Base

if TYPE_CHECKING:
    from db_users import User
class account(Base):
    __tablename__ = 'accounts'
    id: Mapped[int] = mapped_column (primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    currency: Mapped[str] = mapped_column(nullable=False)
    balance: Mapped[float] = mapped_column(default=0.0)
    owner: Mapped['User'] = relationship(back_populates='users')