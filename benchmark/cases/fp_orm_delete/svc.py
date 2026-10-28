def purge(session, models, cutoff):
    return session.query(models.Token).filter(models.Token.expires_at < cutoff).delete()
