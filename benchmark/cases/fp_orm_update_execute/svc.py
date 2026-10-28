from sqlalchemy import update
def retire(db, models, uid):
    db.execute(update(models.Token).where(models.Token.user_id == uid).values(used=True))
