import secrets
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token
from repositories.models import db, User, RevokedToken, PasswordResetToken, Role
import structlog
import re

log = structlog.get_logger()


class AuthError(Exception):
    pass


def _validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _validate_password_strength(password: str) -> list[str]:
    errors = []
    if len(password) < 8:
        errors.append("Senha deve ter ao menos 8 caracteres")
    if not re.search(r"[A-Z]", password):
        errors.append("Incluir ao menos uma letra maiúscula")
    if not re.search(r"\d", password):
        errors.append("Incluir ao menos um número")
    return errors


def register_user(username: str, email: str, password: str, role: str = Role.USER) -> User:
    username = username.strip()[:64]
    email = email.strip().lower()[:128]

    if not username or not email or not password:
        raise AuthError("Campos obrigatórios ausentes")

    if not _validate_email(email):
        raise AuthError("E-mail inválido")

    errors = _validate_password_strength(password)
    if errors:
        raise AuthError("; ".join(errors))

    if role not in Role.ALL:
        role = Role.USER

    if User.query.filter_by(email=email).first():
        # generic message to prevent user enumeration
        raise AuthError("Não foi possível criar a conta. Verifique os dados.")

    if User.query.filter_by(username=username).first():
        raise AuthError("Não foi possível criar a conta. Verifique os dados.")

    user = User(username=username, email=email, role=role)
    user.set_password(password, rounds=current_app.config.get("BCRYPT_ROUNDS", 12))
    db.session.add(user)
    db.session.commit()
    log.info("user_registered", user_id=user.id)
    return user


def login_user(identifier: str, password: str) -> dict:
    """Authenticate by username or email."""
    max_attempts = current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)
    lockout_minutes = current_app.config.get("LOCKOUT_MINUTES", 15)

    # Lookup — avoid revealing whether user exists
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if not user or not user.is_active:
        log.warning("login_failed_unknown", identifier=identifier[:64])
        raise AuthError("Credenciais inválidas")

    if user.is_locked():
        raise AuthError(f"Conta bloqueada. Tente novamente após {lockout_minutes} minutos")

    if not user.check_password(password):
        user.failed_attempts += 1
        if user.failed_attempts >= max_attempts:
            user.locked_until = datetime.utcnow() + timedelta(minutes=lockout_minutes)
            log.warning("account_locked", user_id=user.id)
        db.session.commit()
        raise AuthError("Credenciais inválidas")

    # Success
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.session.commit()

    access_token = create_access_token(identity=user.id, additional_claims={"role": user.role})
    refresh_token = create_refresh_token(identity=user.id)

    log.info("user_login", user_id=user.id)
    return {"access_token": access_token, "refresh_token": refresh_token, "user": user.to_public()}


def logout_token(jti: str):
    revoked = RevokedToken(jti=jti)
    db.session.add(revoked)
    db.session.commit()


def generate_reset_token(email: str) -> str | None:
    user = User.query.filter_by(email=email.lower()).first()
    if not user:
        return None  # silent — prevent enumeration

    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires = datetime.utcnow() + timedelta(hours=1)

    # Invalidate previous tokens
    PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({"used": True})

    entry = PasswordResetToken(user_id=user.id, token_hash=token_hash, expires_at=expires)
    db.session.add(entry)
    db.session.commit()
    return raw_token


def reset_password(raw_token: str, new_password: str):
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    entry = PasswordResetToken.query.filter_by(token_hash=token_hash, used=False).first()

    if not entry or entry.expires_at < datetime.utcnow():
        raise AuthError("Token inválido ou expirado")

    errors = _validate_password_strength(new_password)
    if errors:
        raise AuthError("; ".join(errors))

    user = User.query.get(entry.user_id)
    user.set_password(new_password)
    entry.used = True
    db.session.commit()
    log.info("password_reset", user_id=user.id)
