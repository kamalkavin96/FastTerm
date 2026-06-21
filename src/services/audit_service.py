from repositories.audit_repository import insert_audit, fetch_audit


def audit(username: str, event: str, ip: str, detail: str = ""):
    insert_audit(username, event, ip, detail)


def get_audit_log(limit: int = 100):
    return fetch_audit(limit)