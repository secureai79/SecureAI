#!/usr/bin/env python3
"""Operator tool for the few things support needs a human for. Every change is written to the audit log
(action prefix "admin.") so there is a record of who unlocked or reset what.

Run it with the same environment as the API (DATABASE_URL, JWT_SECRET...), from the project root:

    python scripts/admin.py users                     # list accounts
    python scripts/admin.py show   user@example.com   # one account in detail
    python scripts/admin.py unlock user@example.com   # clear a login lockout
    python scripts/admin.py reset-2fa user@example.com --yes   # lost phone AND recovery codes (verify identity first!)
    python scripts/admin.py verify-email user@example.com
    python scripts/admin.py revoke-sessions user@example.com   # sign the user out everywhere
    python scripts/admin.py set-plan <organization_id> team     # pilot | team | business (limits scale with the plan)
Inside Docker:  docker compose exec app python /app/scripts/admin.py users   (copy scripts/ into the image or mount it)
"""
import argparse
import datetime as dt
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
if (ROOT / "backend" / "app").exists() is False and Path("/app/backend").exists():      # inside the container
    sys.path.insert(0, "/app/backend")


def _ctx():
    from app import auth, models
    from app.database import SessionLocal, init_db
    init_db()
    return SessionLocal(), models, auth


def _audit(db, models, action, user=None, **detail):
    db.add(models.AuditEvent(action=f"admin.{action}"[:64], user_id=user.id if user else None,
                             organization_id=user.organization_id if user else None, detail=detail or None, ip="admin-cli"))
    db.commit()


def _find(db, models, auth, email):
    user = db.query(models.User).filter(models.User.email == auth.normalize_email(email)).first()
    if user is None:
        raise SystemExit(f"No account with e-mail {email!r}")
    return user


def cmd_users(args):
    db, models, auth = _ctx()
    rows = db.query(models.User).order_by(models.User.created_at.asc()).all()
    print(f"{'email':40} {'role':7} {'verified':8} {'2fa':4} {'locked':6} workspaces")
    for u in rows:
        n = db.query(models.Membership).filter(models.Membership.user_id == u.id).count()
        print(f"{u.email:40} {u.role:7} {'yes' if u.email_verified else 'no':8} {'on' if u.mfa_enabled else 'off':4} "
              f"{'yes' if auth.is_locked(u) else 'no':6} {n}")
    print(f"\n{len(rows)} account(s)")


def cmd_show(args):
    db, models, auth = _ctx()
    u = _find(db, models, auth, args.email)
    print(f"id: {u.id}\nemail: {u.email}\nactive workspace: {u.organization_id} ({u.role})\n"
          f"verified: {u.email_verified}\n2FA: {'on' if u.mfa_enabled else 'off'}\n"
          f"failed logins: {u.failed_login_count}  locked until: {u.locked_until}")
    for m in db.query(models.Membership).filter(models.Membership.user_id == u.id):
        org = db.query(models.Organization).filter(models.Organization.id == m.organization_id).first()
        print(f"  member of {org.name if org else '?'} ({m.organization_id}) as {m.role}")


def cmd_unlock(args):
    db, models, auth = _ctx()
    u = _find(db, models, auth, args.email)
    auth.register_successful_login(u)
    db.commit()
    _audit(db, models, "unlock", u)
    print(f"Unlocked {u.email}")


def cmd_reset_2fa(args):
    if not args.yes:
        raise SystemExit("This switches two-factor off for the account. Verify the person's identity first, then re-run with --yes.")
    db, models, auth = _ctx()
    u = _find(db, models, auth, args.email)
    u.totp_secret_enc = None
    u.totp_enabled_at = None
    u.totp_last_step = 0
    db.query(models.MfaRecoveryCode).filter(models.MfaRecoveryCode.user_id == u.id).delete()
    auth.revoke_all_tokens(u)
    auth.register_successful_login(u)
    db.commit()
    _audit(db, models, "reset_2fa", u)
    print(f"Two-factor authentication is now OFF for {u.email} and all sessions were ended. Tell them to turn it back on after logging in.")


def cmd_verify_email(args):
    db, models, auth = _ctx()
    u = _find(db, models, auth, args.email)
    u.email_verified_at = u.email_verified_at or dt.datetime.now(dt.UTC)
    db.commit()
    _audit(db, models, "verify_email", u)
    print(f"{u.email} marked as verified")


def cmd_revoke(args):
    db, models, auth = _ctx()
    u = _find(db, models, auth, args.email)
    auth.revoke_all_tokens(u)
    db.commit()
    _audit(db, models, "revoke_sessions", u)
    print(f"All sessions for {u.email} ended")


def cmd_set_plan(args):
    from app import limits
    if args.plan not in limits.PLAN_MULTIPLIERS:
        raise SystemExit(f"Unknown plan {args.plan!r}; choose one of: {', '.join(limits.PLAN_MULTIPLIERS)}")
    db, models, auth = _ctx()
    org = db.query(models.Organization).filter(models.Organization.id == args.organization_id).first()
    if org is None:
        raise SystemExit("No such organization id")
    org.plan = args.plan
    db.commit()
    db.add(models.AuditEvent(action="admin.set_plan", organization_id=org.id, detail={"plan": args.plan}, ip="admin-cli"))
    db.commit()
    print(f"{org.name} is now on the {args.plan} plan")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("users").set_defaults(fn=cmd_users)
    for name, fn in (("show", cmd_show), ("unlock", cmd_unlock), ("verify-email", cmd_verify_email), ("revoke-sessions", cmd_revoke)):
        p = sub.add_parser(name); p.add_argument("email"); p.set_defaults(fn=fn)
    p = sub.add_parser("reset-2fa"); p.add_argument("email"); p.add_argument("--yes", action="store_true"); p.set_defaults(fn=cmd_reset_2fa)
    p = sub.add_parser("set-plan"); p.add_argument("organization_id"); p.add_argument("plan"); p.set_defaults(fn=cmd_set_plan)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
