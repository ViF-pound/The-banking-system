
from pydantic import BaseModel, Field
class TransactionCreate(BaseModel):
    sender_id: int = Field(...)
    recipient_id: int = Field(..., gt=-1)
    amount: float = Field(gt=0.0)
    description: str = Field(max_length=255)