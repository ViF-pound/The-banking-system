from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from session_model import account
from transaction_model import Transaction
from transaction_shema import TransactionCreate
from db_users import session, User
from auth_models import User
from typing import List

transaction_router = APIRouter()

@app.post("/transaction")
def make_transaction(transaction_create: TransactionCreate, session: Session = Depends(get_session), current_user: User = Depends(get_current_user)):
    sender_account = session.query(account).filter(account.id == transaction_create.sender_id, Account.owner_id == current_user.id).first()
    if not sender_account:
        raise HTTPException(status_code=404, detail="Sender account not found")
    elif sender_account.balance<transaction_create.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    recipient_account = session.query(Account).filter(Account.id == transaction_create.recipient_id).first()
    sender_account.balance -= transaction_create.amount
    if recipient_account:
        recipient_account.balance += transaction_create.amount
    transaction = Transaction(sender_account_id=transaction_create.sender_id,
                              recipient_account_id=transaction_create.recipient_id,
                              amount=transaction_create.amount,
                              description=transaction_create.description)

    session.add(transaction)
    session.commit()
    session.refresh(transaction)
    return {"message": "Transaction successful"}