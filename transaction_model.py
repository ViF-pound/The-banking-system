from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from db_users import session, Base
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from account_models import Account

#модель таблицы с транзакциями на аккаунте юзера
class Transaction(Base):
    __tablename__ = 'transaction'
    id: Mapped[int] = mapped_column(primary_key=True)
    sender_account_id: Mapped[int] = mapped_column (ForeignKey('accounts.id'), nullable=False)
    recipient_account_id: Mapped[int] = mapped_column(ForeignKey('accounts.id'))
    amount: Mapped[float] = mapped_column(nullable=False)
    description: Mapped[str]
    transaction_date:  Mapped[datetime] = mapped_column(default=datetime.now)
    
    sender: Mapped['Account'] = relationship( foreign_keys=[sender_account_id], backref='sent_transactions')
    recipient: Mapped['Account'] = relationship( foreign_keys=[recipient_account_id], backref='received_transactions')