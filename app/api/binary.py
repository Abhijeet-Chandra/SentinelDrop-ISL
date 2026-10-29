"""Deprecated binary API routes retained to return a clear migration response."""

import base64

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.services.auth import get_current_user


router = APIRouter(prefix="/binary", tags=["Binary Transfer"])


class SendBinaryRequest(BaseModel):
    session_id: str
    data: str
    message_type: str
    filename: str | None = None
    mime_type: str | None = None


class ReceiveBinaryRequest(BaseModel):
    session_id: str
    sequence_number: int
    message_type: str
    nonce: str
    ciphertext: str
    filename: str | None = None
    mime_type: str | None = None
    file_size: int | None = None


@router.post("/send")
def send_binary(request: SendBinaryRequest, current_user=Depends(get_current_user)):
    raise HTTPException(
        status_code=410,
        detail="Server-side binary encryption is disabled. Use the browser-encrypted /files/inbox route.",
    )


@router.post("/receive")
def receive_binary(request: ReceiveBinaryRequest, current_user=Depends(get_current_user)):
    raise HTTPException(
        status_code=410,
        detail="Server-side binary decryption is disabled. Decrypt in the paired browser.",
    )
