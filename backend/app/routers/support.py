"""Help & Support: contact form that e-mails the support inbox and confirms to the user."""
import secrets
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, auth, models
from .. import email_service as mail
from ..database import get_db

router = APIRouter(prefix="/support", tags=["support"])

CATEGORIES = {
    "question": "Question",
    "bug": "Something is not working",
    "account": "Account or sign-in",
    "security": "Security concern",
    "feature": "Feature request",
}


class SupportRequest(BaseModel):
    category: Literal["question", "bug", "account", "security", "feature"]
    subject: str = Field(min_length=3, max_length=120)
    message: str = Field(min_length=10, max_length=4000)


def _one_line(value: str) -> str:
    return " ".join(value.split())


@router.get("/info")
def support_info(user: models.User = Depends(auth.get_current_user)):
    return {"email": mail.support_address() or None, "categories": CATEGORIES}


@router.post("/requests")
def create_request(body: SupportRequest, request: Request,
                   user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    to = mail.support_address()
    if not to or not mail.is_configured():
        raise HTTPException(status_code=503, detail="Support email is not configured on this server yet.")
    ticket = "SUP-" + secrets.token_hex(3).upper()
    subject = _one_line(body.subject)
    org = user.organization.name if user.organization else "-"
    details = (
        f"Ticket: {ticket}\nCategory: {CATEGORIES[body.category]}\nFrom: {user.email}\n"
        f"Workspace: {org} ({user.organization_id})\nUser id: {user.id}\n"
        f"Email verified: {'yes' if user.email_verified else 'no'}   Two-factor: {'on' if user.mfa_enabled else 'off'}\n\n"
    )
    plain, html_body = mail._wrap(f"[{ticket}] {subject}", details + body.message, None, None,
                                  "Reply to this e-mail to answer the user directly.")
    sent = mail.send(to, f"[{ticket}] {CATEGORIES[body.category]}: {subject}", plain, html_body, reply_to=user.email)
    if not sent:
        raise HTTPException(status_code=503, detail="We could not send your request right now. Please try again shortly.")
    plain_u, html_u = mail._wrap(
        "We received your message",
        f"Thanks for contacting {mail.app_name()} support. Your reference is {ticket}. We will reply to this address.",
        None, None, f"Your message: {subject}",
    )
    mail.send(user.email, f"We received your request ({ticket})", plain_u, html_u)
    audit.record(db, request, "support.request", user_id=user.id, organization_id=user.organization_id)
    return {"ticket": ticket, "detail": f"Thanks. Your request {ticket} was sent and a confirmation is on its way to {user.email}."}
