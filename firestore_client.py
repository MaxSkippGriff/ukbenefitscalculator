"""
Lazy Firestore client. Returns None if Firebase is unavailable (local dev without ADC).
"""
import logging
log = logging.getLogger(__name__)
_app = None
_db = None
_firestore_mod = None

def get_db():
    global _app, _db, _firestore_mod
    if _db is not None:
        return _db
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
        _firestore_mod = firestore
        if not firebase_admin._apps:
            _app = firebase_admin.initialize_app(credentials.ApplicationDefault())
        else:
            _app = firebase_admin.get_app()
        _db = firestore.client()
        return _db
    except Exception as exc:
        log.warning("Firestore unavailable: %s", exc)
        return None

def server_timestamp():
    if _firestore_mod is None:
        get_db()
    if _firestore_mod is None:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)
    return _firestore_mod.SERVER_TIMESTAMP
