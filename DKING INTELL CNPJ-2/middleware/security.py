import bleach
import re
import structlog
from functools import wraps
from flask import request, jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from repositories.models import User, RevokedToken, db

log = structlog.get_logger()


# ─── Input sanitization ─────────────────────────────────────────────────────

def sanitize_string(value: str, max_length: int = 256) -> str:
    """Strip HTML/JS and limit length."""
    if not isinstance(value, str):
        return ""
    cleaned = bleach.clean(value.strip(), tags=[], strip=True)
    return cleaned[:max_length]


def validate_cnpj_format(cnpj: str) -> bool:
    digits = re.sub(r"\D", "", cnpj)
    if len(digits) != 14:
        return False
    # reject all-same digit CNPJs
    if len(set(digits)) == 1:
        return False
    return True


# ─── Auth decorators ─────────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request(token_location=["cookies"])
        except Exception:
            return jsonify({"status": "error", "message": "Autenticação necessária"}), 401

        jti = get_jwt().get("jti")
        if RevokedToken.query.filter_by(jti=jti).first():
            return jsonify({"status": "error", "message": "Token inválido"}), 401

        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or not user.is_active:
            return jsonify({"status": "error", "message": "Acesso negado"}), 403

        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated(*args, **kwargs):
            if g.current_user.role not in roles:
                log.warning("rbac_denied", user=g.current_user.id, required=roles)
                return jsonify({"status": "error", "message": "Permissão insuficiente"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─── Audit logging ───────────────────────────────────────────────────────────

def audit(action: str, resource: str = None, status: str = "success", details: str = None):
    from repositories.models import AuditLog
    try:
        user_id = None
        try:
            verify_jwt_in_request(token_location=["cookies"], optional=True)
            user_id = get_jwt_identity()
        except Exception:
            pass

        entry = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", "")[:512],
            status=status,
            details=details,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        log.error("audit_log_failed", error=str(exc))


# ─── Request size guard ──────────────────────────────────────────────────────

def limit_payload(max_bytes: int = 16_384):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            content_length = request.content_length
            if content_length and content_length > max_bytes:
                return jsonify({"status": "error", "message": "Payload muito grande"}), 413
            return f(*args, **kwargs)
        return decorated
    return decorator
