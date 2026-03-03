"""
DKING INTEL — app.py  v3.0
Plataforma de inteligência corporativa: cruzamento de dados, mapeamento de sócios,
filiais, colaboradores e análise de redes empresariais.
"""
import os, re, secrets, hashlib, json, http.client, time, urllib.parse
import structlog
from datetime import datetime, timedelta
from functools import wraps
from cachetools import TTLCache
from flask import (Flask, jsonify, request, render_template,
                   make_response, redirect, url_for, session, g)
from flask_jwt_extended import (
    JWTManager, get_jwt, get_jwt_identity,
    create_access_token, create_refresh_token,
    verify_jwt_in_request, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
import bcrypt
import bleach
from dotenv import load_dotenv

load_dotenv()
log = structlog.get_logger()

# ── App & Config ──────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")

IS_PROD = os.environ.get("FLASK_ENV", "development") == "production"

app.config.update(
    SECRET_KEY                   = os.environ.get("SECRET_KEY",
                                       "dking-flask-secret-32chars-2025!!ok"),
    PERMANENT_SESSION_LIFETIME   = timedelta(hours=8),
    SESSION_COOKIE_HTTPONLY      = True,
    SESSION_COOKIE_SAMESITE      = "Strict" if IS_PROD else "Lax",
    SESSION_COOKIE_SECURE        = IS_PROD,

    SQLALCHEMY_DATABASE_URI      = os.environ.get("DATABASE_URL", "sqlite:///dking.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    SQLALCHEMY_ENGINE_OPTIONS    = {"pool_pre_ping": True},

    JWT_SECRET_KEY               = os.environ.get("JWT_SECRET_KEY",
                                       "dking-jwt-secret-32chars-2025!!ok"),
    JWT_TOKEN_LOCATION           = ["cookies"],
    JWT_COOKIE_SECURE            = IS_PROD,
    JWT_COOKIE_SAMESITE          = "Strict" if IS_PROD else "Lax",
    JWT_COOKIE_CSRF_PROTECT      = IS_PROD,
    JWT_ACCESS_TOKEN_EXPIRES     = timedelta(seconds=900),
    JWT_REFRESH_TOKEN_EXPIRES    = timedelta(seconds=604800),

    DEBUG                        = os.environ.get("DEBUG","False").lower()=="true",
    MAX_LOGIN_ATTEMPTS           = int(os.environ.get("MAX_LOGIN_ATTEMPTS", 5)),
    LOCKOUT_MINUTES              = int(os.environ.get("LOCKOUT_MINUTES", 15)),
    BCRYPT_ROUNDS                = int(os.environ.get("BCRYPT_ROUNDS", 12)),

    INVERTEXTO_TOKEN             = os.environ.get("INVERTEXTO_TOKEN", ""),
)

# ── Database ──────────────────────────────────────────────────────────────────
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(64),  unique=True, nullable=False)
    email           = db.Column(db.String(128), unique=True, nullable=False)
    password_hash   = db.Column(db.String(256), nullable=False)
    role            = db.Column(db.String(32),  nullable=False, default="user")
    is_active       = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    last_login      = db.Column(db.DateTime, nullable=True)

    def set_password(self, pw):
        rounds = app.config.get("BCRYPT_ROUNDS", 12)
        self.password_hash = bcrypt.hashpw(
            pw.encode(), bcrypt.gensalt(rounds=rounds)).decode()

    def check_password(self, pw):
        return bcrypt.checkpw(pw.encode(), self.password_hash.encode())

    def is_locked(self):
        return bool(self.locked_until and datetime.utcnow() < self.locked_until)

    def to_dict(self):
        return {"id": self.id, "username": self.username,
                "email": self.email, "role": self.role,
                "created_at": self.created_at.isoformat(),
                "last_login": self.last_login.isoformat() if self.last_login else None,
                "is_active": self.is_active}


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, nullable=True)
    action     = db.Column(db.String(128), nullable=False)
    resource   = db.Column(db.String(256), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    status     = db.Column(db.String(32), default="success")
    details    = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RevokedToken(db.Model):
    __tablename__ = "revoked_tokens"
    id         = db.Column(db.Integer, primary_key=True)
    jti        = db.Column(db.String(256), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, nullable=False)
    token_hash = db.Column(db.String(256), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SavedCompany(db.Model):
    __tablename__ = "saved_companies"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, nullable=False)
    cnpj       = db.Column(db.String(14), nullable=False)
    nome       = db.Column(db.String(256), nullable=True)
    notes      = db.Column(db.Text, nullable=True)
    tags       = db.Column(db.String(512), nullable=True)   # CSV tags
    saved_at   = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'cnpj'),)


class Investigation(db.Model):
    """Agrupa CNPJs em investigações temáticas."""
    __tablename__ = "investigations"
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, nullable=False)
    name        = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cnpjs       = db.Column(db.Text, nullable=True)   # JSON list of CNPJs
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow)


class SearchHistory(db.Model):
    """Histórico de buscas do usuário."""
    __tablename__ = "search_history"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, nullable=False)
    query_type = db.Column(db.String(32), nullable=False)  # cnpj|name|cpf
    query      = db.Column(db.String(256), nullable=False)
    result_nome = db.Column(db.String(256), nullable=True)
    searched_at = db.Column(db.DateTime, default=datetime.utcnow)


# ── Extensions ────────────────────────────────────────────────────────────────
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_revoked(jwt_header, jwt_payload):
    return bool(RevokedToken.query.filter_by(jti=jwt_payload.get("jti")).first())

# Rate limiter
redis_url = os.environ.get("REDIS_URL", "")
limiter_uri = "memory://"
if redis_url.startswith("redis"):
    try:
        import redis as _r; _r.from_url(redis_url, socket_connect_timeout=1).ping()
        limiter_uri = redis_url
    except Exception:
        pass

limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=["300 per minute"], storage_uri=limiter_uri)

allowed_origins = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5000,http://127.0.0.1:5000"
).split(",")

CORS(app, origins=allowed_origins, supports_credentials=True)

# ── Security headers via Talisman ─────────────────────────────────────────────
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    'style-src': ["'self'", "'unsafe-inline'",
                  "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
    'font-src': ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
    'img-src': ["'self'", "data:", "https:"],
    'connect-src': ["'self'"],
}
Talisman(
    app,
    force_https=IS_PROD,
    strict_transport_security=IS_PROD,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'] if IS_PROD else [],
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
)

@app.after_request
def extra_sec_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Permissions-Policy"]     = "geolocation=(), camera=(), microphone=()"
    response.headers["Cache-Control"]          = "no-store, max-age=0"
    return response

# ── DB init ───────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    if not User.query.first():
        try:
            admin = User(username="admin", email="admin@dking.local", role="admin")
            admin.set_password("Admin@1234")
            db.session.add(admin)
            db.session.commit()
            log.info("admin_seeded", user_id=admin.id)
        except Exception as e:
            log.error("seed_failed", error=str(e))

# ── In-memory caches ──────────────────────────────────────────────────────────
_cnpj_cache:   TTLCache = TTLCache(maxsize=512, ttl=600)
_search_cache: TTLCache = TTLCache(maxsize=256, ttl=300)
_socio_cache:  TTLCache = TTLCache(maxsize=256, ttl=600)

# ── Helpers ───────────────────────────────────────────────────────────────────
def _err(msg, code):
    return jsonify({"status": "error", "message": msg}), code

def _audit(action, resource=None, status="success", details=None):
    try:
        uid = session.get("user_id")
        db.session.add(AuditLog(
            user_id=uid, action=action, resource=resource,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent","")[:512],
            status=status, details=details))
        db.session.commit()
    except Exception:
        pass

def _save_history(user_id, qtype, query, result_nome=None):
    try:
        h = SearchHistory(user_id=user_id, query_type=qtype,
                          query=query[:256], result_nome=(result_nome or "")[:256])
        db.session.add(h)
        db.session.commit()
    except Exception:
        db.session.rollback()

def _validate_password(pw):
    errs = []
    if len(pw) < 8:                  errs.append("Mín. 8 caracteres")
    if not re.search(r"[A-Z]", pw): errs.append("Ao menos 1 maiúscula")
    if not re.search(r"\d", pw):    errs.append("Ao menos 1 número")
    return errs

def _sanitize(v, max_len=256):
    if not isinstance(v, str): return ""
    return bleach.clean(v.strip(), tags=[], strip=True)[:max_len]

def _require_session():
    return "user_id" in session

# ════════════════════════════════════════════════════════════════════════════
# CNPJ & COMPANY DATA SERVICES
# ════════════════════════════════════════════════════════════════════════════

def _https_get(host, path, timeout=10, headers=None):
    h = {"Accept": "application/json", "User-Agent": "DkingIntel/3.0"}
    if headers:
        h.update(headers)
    conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request("GET", path, headers=h)
        res = conn.getresponse()
        if res.status == 429:
            raise Exception(f"Rate limited by {host}")
        if res.status == 404:
            raise Exception(f"CNPJ não encontrado em {host}")
        if res.status != 200:
            raise Exception(f"HTTP {res.status} de {host}")
        raw = res.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        if not data:
            raise Exception("Resposta vazia")
        return data
    finally:
        conn.close()


def _query_cnpjws(cnpj: str) -> dict:
    """publica.cnpj.ws — gratuita, sem autenticação"""
    d = _https_get("publica.cnpj.ws", f"/cnpj/{cnpj}")
    est = d.get("estabelecimento", {})
    emp = d.get("empresa", {})

    socios = []
    for s in emp.get("socios", []):
        socios.append({
            "nome": s.get("nome", ""),
            "qual": s.get("qualificacao_socio", {}).get("descricao", "") if isinstance(s.get("qualificacao_socio"), dict) else str(s.get("qualificacao_socio", "")),
            "cpf_cnpj_socio": s.get("cpf_cnpj_socio", ""),
            "pais": s.get("pais", {}).get("descricao", "") if isinstance(s.get("pais"), dict) else "",
            "data_entrada": s.get("data_entrada_sociedade", ""),
        })

    ativs_sec = []
    for a in est.get("atividades_secundarias", []):
        ativs_sec.append({"code": a.get("id",""), "text": a.get("descricao","")})

    # filiais — cnpj.ws retorna filiais no campo de filiais
    filiais = []
    for f in d.get("filiais", []):
        filiais.append({
            "cnpj": f.get("cnpj",""),
            "situacao": f.get("situacao_cadastral", {}).get("descricao","") if isinstance(f.get("situacao_cadastral"), dict) else "",
            "municipio": f.get("cidade", {}).get("nome","") if isinstance(f.get("cidade"), dict) else "",
            "uf": f.get("estado", {}).get("sigla","") if isinstance(f.get("estado"), dict) else "",
        })

    return {
        "cnpj": re.sub(r"\D","",d.get("cnpj",cnpj) or cnpj),
        "nome": emp.get("razao_social") or est.get("nome_fantasia"),
        "fantasia": est.get("nome_fantasia"),
        "situacao": est.get("situacao_cadastral",""),
        "abertura": est.get("data_inicio_atividade",""),
        "natureza_juridica": emp.get("natureza_juridica",{}).get("descricao","") if isinstance(emp.get("natureza_juridica"),dict) else str(emp.get("natureza_juridica","")),
        "capital_social": str(emp.get("capital_social","")),
        "porte": emp.get("porte",{}).get("descricao","") if isinstance(emp.get("porte"),dict) else str(emp.get("porte","")),
        "logradouro": est.get("logradouro",""),
        "numero": est.get("numero",""),
        "complemento": est.get("complemento",""),
        "bairro": est.get("bairro",""),
        "municipio": est.get("cidade",{}).get("nome","") if isinstance(est.get("cidade"),dict) else "",
        "uf": est.get("estado",{}).get("sigla","") if isinstance(est.get("estado"),dict) else "",
        "cep": est.get("cep",""),
        "email": est.get("email",""),
        "telefone": est.get("ddd1","") + est.get("telefone1","") if est.get("telefone1") else "",
        "qsa": socios,
        "atividade_principal": [{"code": est.get("atividade_principal",{}).get("id",""),
                                  "text": est.get("atividade_principal",{}).get("descricao","")}]
                                if isinstance(est.get("atividade_principal"),dict) else [],
        "atividades_secundarias": ativs_sec,
        "filiais": filiais,
        "simples_nacional": d.get("simples",{}).get("simples","") if isinstance(d.get("simples"),dict) else "",
        "mei": d.get("simples",{}).get("mei","") if isinstance(d.get("simples"),dict) else "",
        "optante_simples": d.get("simples",{}).get("optante","") if isinstance(d.get("simples"),dict) else "",
        "_source": "cnpjws",
    }


def _query_cnpja_open(cnpj: str) -> dict:
    """open.cnpja.com — gratuita"""
    d = _https_get("open.cnpja.com", f"/office/{cnpj}")
    company = d.get("company", {})
    address = d.get("address", {})

    socios = []
    for m in company.get("members", []):
        socios.append({
            "nome": m.get("name",""),
            "qual": m.get("role",{}).get("text","") if isinstance(m.get("role"),dict) else "",
            "cpf_cnpj_socio": m.get("taxId",""),
            "pais": m.get("country",{}).get("name","") if isinstance(m.get("country"),dict) else "",
            "data_entrada": m.get("since",""),
        })

    return {
        "cnpj": re.sub(r"\D","",d.get("taxId",cnpj) or cnpj),
        "nome": company.get("name"),
        "fantasia": d.get("alias"),
        "situacao": d.get("status",{}).get("text","") if isinstance(d.get("status"),dict) else "",
        "abertura": d.get("founded",""),
        "natureza_juridica": company.get("nature",{}).get("text","") if isinstance(company.get("nature"),dict) else "",
        "capital_social": str(company.get("equity","")),
        "porte": company.get("size",{}).get("text","") if isinstance(company.get("size"),dict) else "",
        "logradouro": address.get("street",""),
        "numero": address.get("number",""),
        "complemento": address.get("details",""),
        "bairro": address.get("district",""),
        "municipio": address.get("city",""),
        "uf": address.get("state",""),
        "cep": address.get("zip",""),
        "email": d.get("emails",[{}])[0].get("address","") if d.get("emails") else "",
        "telefone": d.get("phones",[{}])[0].get("number","") if d.get("phones") else "",
        "qsa": socios,
        "atividade_principal": [{"code": d.get("mainActivity",{}).get("id",""),
                                  "text": d.get("mainActivity",{}).get("text","")}]
                                if d.get("mainActivity") else [],
        "atividades_secundarias": [{"code":a.get("id",""),"text":a.get("text","")}
                                    for a in d.get("sideActivities",[])],
        "filiais": [],
        "_source": "cnpja_open",
    }


def _query_brasilapi(cnpj: str) -> dict:
    d = _https_get("brasilapi.com.br", f"/api/cnpj/v1/{cnpj}")
    socios = []
    for s in d.get("qsa", []):
        socios.append({
            "nome": s.get("nome_socio",""),
            "qual": s.get("qualificacao_socio",""),
            "cpf_cnpj_socio": s.get("cnpj_cpf_do_socio",""),
            "pais": "",
            "data_entrada": "",
        })
    return {
        "cnpj": re.sub(r"\D","",d.get("cnpj",cnpj) or cnpj),
        "nome": d.get("razao_social"),
        "fantasia": d.get("nome_fantasia"),
        "situacao": d.get("descricao_situacao_cadastral"),
        "abertura": d.get("data_inicio_atividade"),
        "natureza_juridica": (d.get("natureza_juridica",{}).get("descricao")
                               if isinstance(d.get("natureza_juridica"),dict)
                               else d.get("natureza_juridica")),
        "capital_social": str(d.get("capital_social","")),
        "porte": d.get("porte"),
        "logradouro": d.get("logradouro"), "numero": d.get("numero"),
        "complemento": d.get("complemento"), "bairro": d.get("bairro"),
        "municipio": d.get("municipio"), "uf": d.get("uf"),
        "cep": d.get("cep"), "email": d.get("email"),
        "telefone": d.get("ddd_telefone_1",""),
        "qsa": socios,
        "atividade_principal": [{"code":d.get("cnae_fiscal",""),
                                  "text":d.get("cnae_fiscal_descricao","")}],
        "atividades_secundarias": [{"code":a.get("codigo",""),"text":a.get("descricao","")}
                                    for a in d.get("cnaes_secundarios",[])],
        "filiais": [],
        "_source": "brasilapi",
    }


def _query_receitaws(cnpj: str) -> dict:
    d = _https_get("receitaws.com.br", f"/v1/cnpj/{cnpj}")
    socios = []
    for s in d.get("qsa", []):
        socios.append({
            "nome": s.get("nome",""),
            "qual": s.get("qual",""),
            "cpf_cnpj_socio": s.get("cpf_representante_legal",""),
            "pais": s.get("pais_origem",""),
            "data_entrada": "",
        })
    return {
        "cnpj": re.sub(r"\D","",d.get("cnpj",cnpj) or cnpj),
        "nome": d.get("nome"),
        "fantasia": d.get("fantasia"),
        "situacao": d.get("situacao"),
        "abertura": d.get("abertura"),
        "natureza_juridica": d.get("natureza_juridica"),
        "capital_social": d.get("capital_social",""),
        "porte": d.get("porte"),
        "logradouro": d.get("logradouro"), "numero": d.get("numero"),
        "complemento": d.get("complemento"), "bairro": d.get("bairro"),
        "municipio": d.get("municipio"), "uf": d.get("uf"),
        "cep": d.get("cep"), "email": d.get("email"),
        "telefone": d.get("telefone",""),
        "qsa": socios,
        "atividade_principal": d.get("atividade_principal",[]),
        "atividades_secundarias": d.get("atividades_secundarias",[]),
        "filiais": [],
        "_source": "receitaws",
    }


def _fetch_retry(fetcher, *args, retries=2, delay=0.5):
    last_err = None
    for i in range(retries+1):
        try:
            return fetcher(*args)
        except Exception as e:
            last_err = e
            if i < retries: time.sleep(delay*(i+1))
    raise last_err


def consultar_cnpj(cnpj: str) -> dict:
    cnpj = re.sub(r"\D","",cnpj)
    if not re.fullmatch(r"\d{14}", cnpj) or len(set(cnpj))==1:
        raise ValueError("CNPJ inválido")

    ckey = hashlib.md5(cnpj.encode()).hexdigest()
    if ckey in _cnpj_cache:
        return _cnpj_cache[ckey]

    # Priority: cnpjws (more data) → cnpja_open → brasilapi → receitaws
    apis = [
        ("cnpjws", _query_cnpjws),
        ("cnpja_open", _query_cnpja_open),
        ("brasilapi", _query_brasilapi),
        ("receitaws", _query_receitaws),
    ]
    errs = []
    for name, fetcher in apis:
        try:
            raw = _fetch_retry(fetcher, cnpj)
            if raw and raw.get("nome"):
                _cnpj_cache[ckey] = raw
                log.info("cnpj_fetched", source=name)
                return raw
        except Exception as e:
            errs.append(f"{name}: {e}")
            log.warning("cnpj_api_failed", api=name, error=str(e))

    raise Exception(f"Todas as APIs falharam: {errs}")


def search_by_name(query: str) -> list:
    """Search companies by name."""
    q = _sanitize(query, 100).strip()
    if not q or len(q) < 2:
        raise ValueError("Query muito curta")

    ckey = hashlib.md5(f"search:{q.lower()}".encode()).hexdigest()
    if ckey in _search_cache:
        return _search_cache[ckey]

    # Try brasilapi company search
    try:
        encoded = urllib.parse.quote(q)
        d = _https_get("brasilapi.com.br", f"/api/cnpj/v1/busca?query={encoded}&offset=0&limit=20", timeout=10)
        results = []
        items = d if isinstance(d, list) else d.get("results", d.get("data", []))
        for item in items[:20]:
            results.append({
                "cnpj": re.sub(r"\D","",item.get("cnpj","") or ""),
                "nome": item.get("razao_social") or item.get("nome",""),
                "municipio": item.get("municipio",""),
                "uf": item.get("uf",""),
                "situacao": item.get("descricao_situacao_cadastral",""),
            })
        if results:
            _search_cache[ckey] = results
            return results
    except Exception as e:
        log.warning("search_brasilapi_failed", error=str(e))

    # Fallback: bff.cnpja.com
    try:
        encoded = q.replace(" ","+")
        d = _https_get("bff.cnpja.com", f"/search?query={encoded}", timeout=10)
        items = d if isinstance(d, list) else d.get("items", d.get("data", []))
        results = []
        for item in items[:20]:
            results.append({
                "cnpj": re.sub(r"\D","",item.get("taxId",item.get("cnpj","")) or ""),
                "nome": item.get("alias") or item.get("name",""),
                "municipio": item.get("city",""),
                "uf": item.get("state",""),
                "situacao": item.get("status",""),
            })
        _search_cache[ckey] = results
        return results
    except Exception as e:
        log.warning("search_bff_cnpja_failed", error=str(e))
        return []


def buscar_empresas_por_socio(nome_socio: str) -> list:
    """Busca empresas cujo sócio tem determinado nome (via cnpjws/brasilapi)."""
    ckey = hashlib.md5(f"socio:{nome_socio.lower()}".encode()).hexdigest()
    if ckey in _socio_cache:
        return _socio_cache[ckey]

    try:
        encoded = urllib.parse.quote(nome_socio)
        # Tenta brasilapi sócios
        d = _https_get("brasilapi.com.br", f"/api/cnpj/v1/socios?nome={encoded}", timeout=10)
        items = d if isinstance(d, list) else d.get("data", [])
        results = []
        for item in items[:30]:
            results.append({
                "cnpj": re.sub(r"\D","",item.get("cnpj","") or ""),
                "nome_empresa": item.get("razao_social",""),
                "qualificacao": item.get("qualificacao_socio",""),
            })
        _socio_cache[ckey] = results
        return results
    except Exception as e:
        log.warning("socio_search_failed", error=str(e))
        return []


def get_filiais(cnpj_raiz: str) -> list:
    """Busca filiais de um CNPJ (8 primeiros dígitos = raiz)."""
    raiz = re.sub(r"\D","",cnpj_raiz)[:8]
    try:
        d = _https_get("publica.cnpj.ws", f"/cnpj/{raiz}0001", timeout=10)
        filiais_raw = d.get("filiais", [])
        filiais = []
        for f in filiais_raw:
            filiais.append({
                "cnpj": f.get("cnpj",""),
                "situacao": f.get("situacao_cadastral",{}).get("descricao","") if isinstance(f.get("situacao_cadastral"),dict) else "",
                "municipio": f.get("cidade",{}).get("nome","") if isinstance(f.get("cidade"),dict) else "",
                "uf": f.get("estado",{}).get("sigla","") if isinstance(f.get("estado"),dict) else "",
                "fantasia": f.get("nome_fantasia",""),
            })
        return filiais
    except Exception as e:
        log.warning("filiais_fetch_failed", error=str(e))
        return []


def build_social_links(company_name: str, cnpj: str = None) -> dict:
    if not company_name:
        return {}
    name_clean   = re.sub(r"[^\w\s]", "", company_name).strip()
    name_encoded = urllib.parse.quote(name_clean)
    name_slug    = name_clean.lower().replace(" ","-")

    return {
        "linkedin_company":   f"https://www.linkedin.com/company/{name_slug}",
        "linkedin_search":    f"https://www.linkedin.com/search/results/companies/?keywords={name_encoded}",
        "linkedin_people":    f"https://www.linkedin.com/search/results/people/?keywords={name_encoded}",
        "instagram":          f"https://www.instagram.com/{name_clean.replace(' ','').lower()}/",
        "instagram_tag":      f"https://www.instagram.com/explore/tags/{name_clean.replace(' ','').lower()}/",
        "facebook":           f"https://www.facebook.com/search/pages?q={name_encoded}",
        "twitter":            f"https://twitter.com/search?q=%22{name_encoded}%22&f=user",
        "google_geral":       f"https://www.google.com/search?q={name_encoded}",
        "google_social":      f"https://www.google.com/search?q=%22{name_encoded}%22+site:linkedin.com+OR+site:instagram.com+OR+site:facebook.com",
        "google_noticias":    f"https://news.google.com/search?q={name_encoded}",
        "youtube":            f"https://www.youtube.com/results?search_query={name_encoded}",
        "reclameaqui":        f"https://www.reclameaqui.com.br/busca/?q={name_encoded}",
        "tiktok":             f"https://www.tiktok.com/search?q={name_encoded}",
        "glassdoor":          f"https://www.glassdoor.com.br/Avalia%C3%A7%C3%B5es/index.htm?typedKeyword={name_encoded}",
        "indeed":             f"https://br.indeed.com/cmp/{name_slug}",
        "escavador":          f"https://www.escavador.com/sobre?entity_name={name_encoded}",
        "jusbrasil":          f"https://www.jusbrasil.com.br/consulta-processual/search?q={name_encoded}",
    }


# ════════════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    return render_template("index.html")


@app.route("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/admin")
def admin_page():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login_page"))
    return render_template("admin.html")


# ════════════════════════════════════════════════════════════════════════════
# AUTH API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def api_login():
    body = request.get_json(silent=True) or {}
    identifier = _sanitize(body.get("identifier",""), 128)
    password   = body.get("password","")

    if not identifier or not password:
        return _err("Preencha todos os campos", 400)

    max_att = app.config["MAX_LOGIN_ATTEMPTS"]
    lockout = app.config["LOCKOUT_MINUTES"]

    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if not user or not user.is_active:
        _audit("login_failed", identifier, "fail", "user_not_found")
        return _err("Credenciais inválidas", 401)

    if user.is_locked():
        _audit("login_blocked", identifier, "fail", "account_locked")
        return _err(f"Conta bloqueada. Tente em {lockout} min.", 423)

    if not user.check_password(password):
        user.failed_attempts += 1
        if user.failed_attempts >= max_att:
            user.locked_until = datetime.utcnow() + timedelta(minutes=lockout)
            log.warning("account_locked", user_id=user.id)
        db.session.commit()
        _audit("login_failed", identifier, "fail", "bad_password")
        return _err("Credenciais inválidas", 401)

    user.failed_attempts = 0
    user.locked_until    = None
    user.last_login      = datetime.utcnow()
    db.session.commit()

    session.permanent = True
    session["user_id"]  = user.id
    session["username"] = user.username
    session["role"]     = user.role

    _audit("login_success", identifier)
    return jsonify({"status":"ok","user": user.to_dict()}), 200


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    _audit("logout")
    session.clear()
    return jsonify({"status":"ok"}), 200


@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if "user_id" not in session:
        return _err("Não autenticado", 401)
    user = User.query.get(session["user_id"])
    if not user:
        return _err("Usuário não encontrado", 404)
    return jsonify({"status":"ok","user": user.to_dict()})


@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per minute")
def api_register():
    # Only admins can register new users (or open registration in dev)
    if "user_id" not in session or session.get("role") not in ("admin",):
        return _err("Apenas administradores podem criar usuários", 403)

    body = request.get_json(silent=True) or {}
    username = _sanitize(body.get("username",""), 64)
    email    = _sanitize(body.get("email",""), 128).lower()
    password = body.get("password","")
    role     = _sanitize(body.get("role","user"), 32)

    if not username or not email or not password:
        return _err("Campos obrigatórios ausentes", 400)

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return _err("E-mail inválido", 400)

    errs = _validate_password(password)
    if errs:
        return _err("; ".join(errs), 400)

    if role not in ("admin","operator","user"):
        role = "user"

    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return _err("Usuário ou e-mail já cadastrado", 409)

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    _audit("user_created", f"username={username}")
    return jsonify({"status":"ok","user": user.to_dict()}), 201


@app.route("/api/auth/change-password", methods=["POST"])
@limiter.limit("5 per minute")
def api_change_password():
    if "user_id" not in session:
        return _err("Autenticação necessária", 401)

    body = request.get_json(silent=True) or {}
    current_pw  = body.get("current_password","")
    new_pw      = body.get("new_password","")

    user = User.query.get(session["user_id"])
    if not user or not user.check_password(current_pw):
        return _err("Senha atual incorreta", 401)

    errs = _validate_password(new_pw)
    if errs:
        return _err("; ".join(errs), 400)

    user.set_password(new_pw)
    db.session.commit()
    _audit("password_changed")
    return jsonify({"status":"ok","message":"Senha alterada com sucesso"})


# ════════════════════════════════════════════════════════════════════════════
# COMPANY INTEL API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/cnpj/<cnpj>", methods=["GET"])
@limiter.limit("60 per minute")
def api_cnpj(cnpj):
    if not _require_session():
        return _err("Autenticação necessária", 401)

    cnpj_clean = re.sub(r"\D","",_sanitize(cnpj, 20))
    if len(cnpj_clean) != 14:
        return _err("CNPJ deve ter 14 dígitos", 400)

    try:
        data = consultar_cnpj(cnpj_clean)
        _audit("cnpj_query", cnpj_clean)
        _save_history(session["user_id"], "cnpj", cnpj_clean, data.get("nome"))
        return jsonify({"status":"ok","data":data}), 200
    except ValueError as e:
        return _err(str(e), 400)
    except Exception as e:
        log.error("cnpj_query_error", error=str(e))
        return _err("Erro ao consultar CNPJ. Tente novamente.", 503)


@app.route("/api/cnpj/<cnpj>/filiais", methods=["GET"])
@limiter.limit("30 per minute")
def api_filiais(cnpj):
    if not _require_session():
        return _err("Autenticação necessária", 401)

    cnpj_clean = re.sub(r"\D","",_sanitize(cnpj, 20))
    try:
        filiais = get_filiais(cnpj_clean)
        _audit("filiais_query", cnpj_clean)
        return jsonify({"status":"ok","data":filiais,"total":len(filiais)})
    except Exception as e:
        return _err("Erro ao buscar filiais", 503)


@app.route("/api/cnpj/<cnpj>/social", methods=["GET"])
@limiter.limit("60 per minute")
def api_social(cnpj):
    if not _require_session():
        return _err("Autenticação necessária", 401)
    cnpj_clean = re.sub(r"\D","",_sanitize(cnpj, 20))
    try:
        data = _cnpj_cache.get(hashlib.md5(cnpj_clean.encode()).hexdigest())
        nome = data.get("nome","") if data else ""
    except Exception:
        nome = ""
    nome_param = _sanitize(request.args.get("nome",""), 256) or nome
    links = build_social_links(nome_param, cnpj_clean)
    return jsonify({"status":"ok","links":links})


@app.route("/api/search/name", methods=["GET"])
@limiter.limit("30 per minute")
def api_search_name():
    if not _require_session():
        return _err("Autenticação necessária", 401)

    query = _sanitize(request.args.get("q",""), 100).strip()
    if len(query) < 2:
        return _err("Informe ao menos 2 caracteres", 400)

    try:
        data = search_by_name(query)
        _audit("name_search", query)
        _save_history(session["user_id"], "name", query)
        return jsonify({"status":"ok","data":data}), 200
    except Exception as e:
        log.error("name_search_error", error=str(e))
        return _err("Erro ao buscar empresas", 503)


@app.route("/api/search/socio", methods=["GET"])
@limiter.limit("20 per minute")
def api_search_socio():
    if not _require_session():
        return _err("Autenticação necessária", 401)

    nome = _sanitize(request.args.get("nome",""), 128).strip()
    if len(nome) < 3:
        return _err("Informe ao menos 3 caracteres", 400)

    try:
        data = buscar_empresas_por_socio(nome)
        _audit("socio_search", nome)
        _save_history(session["user_id"], "socio", nome)
        return jsonify({"status":"ok","data":data,"total":len(data)}), 200
    except Exception as e:
        log.error("socio_search_error", error=str(e))
        return _err("Erro ao buscar por sócio", 503)


@app.route("/api/cross-reference", methods=["POST"])
@limiter.limit("10 per minute")
def api_cross_reference():
    """Cruzamento de dados: recebe lista de CNPJs e retorna visão consolidada."""
    if not _require_session():
        return _err("Autenticação necessária", 401)

    body = request.get_json(silent=True) or {}
    cnpjs = body.get("cnpjs", [])
    if not isinstance(cnpjs, list) or len(cnpjs) == 0:
        return _err("Forneça uma lista de CNPJs", 400)
    if len(cnpjs) > 10:
        return _err("Máximo de 10 CNPJs por cruzamento", 400)

    results = []
    socios_map = {}  # sócio → lista de empresas

    for raw_cnpj in cnpjs:
        cnpj_clean = re.sub(r"\D","",_sanitize(str(raw_cnpj), 20))
        if len(cnpj_clean) != 14:
            results.append({"cnpj": cnpj_clean, "error": "CNPJ inválido"})
            continue
        try:
            data = consultar_cnpj(cnpj_clean)
            results.append({"cnpj": cnpj_clean, "data": data})
            for s in data.get("qsa", []):
                nome_s = s.get("nome","").strip().upper()
                if nome_s:
                    socios_map.setdefault(nome_s, []).append({
                        "cnpj": cnpj_clean,
                        "empresa": data.get("nome",""),
                        "qualificacao": s.get("qual",""),
                    })
        except Exception as e:
            results.append({"cnpj": cnpj_clean, "error": str(e)})

    # Socios em comum (aparecem em 2+ empresas)
    socios_comuns = {k: v for k, v in socios_map.items() if len(v) >= 2}

    _audit("cross_reference", details=f"{len(cnpjs)} CNPJs")
    return jsonify({
        "status": "ok",
        "results": results,
        "socios_comuns": socios_comuns,
        "total_companies": len(results),
        "total_socios_comuns": len(socios_comuns),
    })


# ════════════════════════════════════════════════════════════════════════════
# SAVED COMPANIES API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/saved", methods=["GET"])
def api_saved_list():
    if not _require_session():
        return _err("Autenticação necessária", 401)
    items = SavedCompany.query.filter_by(user_id=session["user_id"])\
                .order_by(SavedCompany.saved_at.desc()).all()
    data = [{"id":i.id,"cnpj":i.cnpj,"nome":i.nome,
              "notes":i.notes,"tags":i.tags,"saved_at":i.saved_at.isoformat()} for i in items]
    return jsonify({"status":"ok","data":data})


@app.route("/api/saved", methods=["POST"])
@limiter.limit("30 per minute")
def api_saved_add():
    if not _require_session():
        return _err("Autenticação necessária", 401)
    body = request.get_json(silent=True) or {}
    cnpj  = re.sub(r"\D","",_sanitize(body.get("cnpj",""), 20))
    nome  = _sanitize(body.get("nome",""), 256)
    notes = _sanitize(body.get("notes",""), 500)
    tags  = _sanitize(body.get("tags",""), 256)
    if len(cnpj) != 14:
        return _err("CNPJ inválido", 400)
    try:
        item = SavedCompany(user_id=session["user_id"], cnpj=cnpj,
                            nome=nome, notes=notes, tags=tags)
        db.session.add(item)
        db.session.commit()
        return jsonify({"status":"ok","message":"Empresa salva!"}), 201
    except Exception:
        db.session.rollback()
        return _err("Empresa já salva ou erro ao salvar", 400)


@app.route("/api/saved/<int:sid>", methods=["PUT"])
def api_saved_update(sid):
    if not _require_session():
        return _err("Autenticação necessária", 401)
    item = SavedCompany.query.filter_by(id=sid, user_id=session["user_id"]).first()
    if not item:
        return _err("Não encontrado", 404)
    body = request.get_json(silent=True) or {}
    if "notes" in body: item.notes = _sanitize(body["notes"], 500)
    if "tags"  in body: item.tags  = _sanitize(body["tags"], 256)
    db.session.commit()
    return jsonify({"status":"ok"})


@app.route("/api/saved/<int:sid>", methods=["DELETE"])
def api_saved_delete(sid):
    if not _require_session():
        return _err("Autenticação necessária", 401)
    item = SavedCompany.query.filter_by(id=sid, user_id=session["user_id"]).first()
    if not item:
        return _err("Não encontrado", 404)
    db.session.delete(item)
    db.session.commit()
    return jsonify({"status":"ok"})


# ════════════════════════════════════════════════════════════════════════════
# INVESTIGATIONS API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/investigations", methods=["GET"])
def api_inv_list():
    if not _require_session():
        return _err("Autenticação necessária", 401)
    items = Investigation.query.filter_by(user_id=session["user_id"])\
                .order_by(Investigation.updated_at.desc()).all()
    data = [{"id":i.id,"name":i.name,"description":i.description,
              "cnpjs":json.loads(i.cnpjs or "[]"),
              "created_at":i.created_at.isoformat(),
              "updated_at":i.updated_at.isoformat()} for i in items]
    return jsonify({"status":"ok","data":data})


@app.route("/api/investigations", methods=["POST"])
def api_inv_create():
    if not _require_session():
        return _err("Autenticação necessária", 401)
    body = request.get_json(silent=True) or {}
    name = _sanitize(body.get("name",""), 128)
    if not name:
        return _err("Nome da investigação é obrigatório", 400)
    inv = Investigation(
        user_id=session["user_id"],
        name=name,
        description=_sanitize(body.get("description",""), 512),
        cnpjs=json.dumps([])
    )
    db.session.add(inv)
    db.session.commit()
    return jsonify({"status":"ok","id":inv.id}), 201


@app.route("/api/investigations/<int:iid>", methods=["PUT"])
def api_inv_update(iid):
    if not _require_session():
        return _err("Autenticação necessária", 401)
    inv = Investigation.query.filter_by(id=iid, user_id=session["user_id"]).first()
    if not inv:
        return _err("Investigação não encontrada", 404)
    body = request.get_json(silent=True) or {}
    if "name"        in body: inv.name        = _sanitize(body["name"], 128)
    if "description" in body: inv.description = _sanitize(body["description"], 512)
    if "cnpjs"       in body:
        clean = [re.sub(r"\D","",c) for c in body["cnpjs"] if isinstance(c,str)]
        inv.cnpjs = json.dumps(clean[:50])
    inv.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status":"ok"})


@app.route("/api/investigations/<int:iid>", methods=["DELETE"])
def api_inv_delete(iid):
    if not _require_session():
        return _err("Autenticação necessária", 401)
    inv = Investigation.query.filter_by(id=iid, user_id=session["user_id"]).first()
    if not inv:
        return _err("Investigação não encontrada", 404)
    db.session.delete(inv)
    db.session.commit()
    return jsonify({"status":"ok"})


# ════════════════════════════════════════════════════════════════════════════
# HISTORY API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/history", methods=["GET"])
def api_history():
    if not _require_session():
        return _err("Autenticação necessária", 401)
    limit = min(100, int(request.args.get("limit", 50)))
    items = SearchHistory.query.filter_by(user_id=session["user_id"])\
                .order_by(SearchHistory.searched_at.desc()).limit(limit).all()
    data = [{"id":i.id,"query_type":i.query_type,"query":i.query,
              "result_nome":i.result_nome,
              "searched_at":i.searched_at.isoformat()} for i in items]
    return jsonify({"status":"ok","data":data})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    if not _require_session():
        return _err("Autenticação necessária", 401)
    SearchHistory.query.filter_by(user_id=session["user_id"]).delete()
    db.session.commit()
    return jsonify({"status":"ok","message":"Histórico limpo"})


# ════════════════════════════════════════════════════════════════════════════
# ADMIN API
# ════════════════════════════════════════════════════════════════════════════

def _admin_required():
    if "user_id" not in session or session.get("role") != "admin":
        return None, _err("Acesso negado", 403)
    u = User.query.get(session["user_id"])
    if not u or not u.is_active:
        return None, _err("Acesso negado", 403)
    return u, None


@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    _, err = _admin_required()
    if err: return err
    users = User.query.order_by(User.created_at.desc()).all()
    data = []
    for u in users:
        d = u.to_dict()
        d["locked_until"]    = u.locked_until.isoformat() if u.locked_until else None
        d["failed_attempts"] = u.failed_attempts
        data.append(d)
    return jsonify({"status":"ok","data":data})


@app.route("/api/admin/users", methods=["POST"])
@limiter.limit("10 per minute")
def admin_create_user():
    _, err = _admin_required()
    if err: return err
    return api_register()


@app.route("/api/admin/users/<int:uid>", methods=["PUT"])
def admin_update_user(uid):
    current, err = _admin_required()
    if err: return err
    user = User.query.get(uid)
    if not user: return _err("Usuário não encontrado", 404)
    body = request.get_json(silent=True) or {}
    if "role" in body and body["role"] in ["admin","operator","user"]:
        user.role = body["role"]
    if "email" in body:
        user.email = _sanitize(body["email"],128).lower()
    if body.get("password"):
        errs = _validate_password(body["password"])
        if errs: return _err("; ".join(errs), 400)
        user.set_password(body["password"])
    db.session.commit()
    _audit("admin_update_user", f"user_id={uid}")
    return jsonify({"status":"ok","user":user.to_dict()})


@app.route("/api/admin/users/<int:uid>/deactivate", methods=["POST"])
def admin_deactivate(uid):
    current, err = _admin_required()
    if err: return err
    user = User.query.get(uid)
    if not user: return _err("Não encontrado", 404)
    if user.id == current.id: return _err("Não pode desativar a si mesmo", 400)
    user.is_active = False
    db.session.commit()
    _audit("admin_deactivate_user", f"user_id={uid}")
    return jsonify({"status":"ok"})


@app.route("/api/admin/users/<int:uid>/activate", methods=["POST"])
def admin_activate(uid):
    _, err = _admin_required()
    if err: return err
    user = User.query.get(uid)
    if not user: return _err("Não encontrado", 404)
    user.is_active    = True
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    _audit("admin_activate_user", f"user_id={uid}")
    return jsonify({"status":"ok"})


@app.route("/api/admin/users/<int:uid>/unlock", methods=["POST"])
def admin_unlock(uid):
    _, err = _admin_required()
    if err: return err
    user = User.query.get(uid)
    if not user: return _err("Não encontrado", 404)
    user.failed_attempts = 0
    user.locked_until    = None
    db.session.commit()
    _audit("admin_unlock_user", f"user_id={uid}")
    return jsonify({"status":"ok","message":"Conta desbloqueada"})


@app.route("/api/admin/audit-log", methods=["GET"])
def admin_audit_log():
    _, err = _admin_required()
    if err: return err
    page = max(1, int(request.args.get("page",1)))
    per  = min(100, int(request.args.get("per",50)))
    q    = AuditLog.query.order_by(AuditLog.created_at.desc())
    total = q.count()
    logs  = q.offset((page-1)*per).limit(per).all()
    data = [{"id":l.id,"user_id":l.user_id,"action":l.action,
             "resource":l.resource,"ip_address":l.ip_address,
             "status":l.status,"details":l.details,
             "user_agent":l.user_agent,
             "created_at":l.created_at.isoformat()} for l in logs]
    return jsonify({"status":"ok","data":data,"total":total,"page":page})


@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    _, err = _admin_required()
    if err: return err
    total_users   = User.query.count()
    active_users  = User.query.filter_by(is_active=True).count()
    locked_users  = User.query.filter(User.locked_until > datetime.utcnow()).count()
    total_queries = AuditLog.query.filter_by(action="cnpj_query").count()
    today         = datetime.utcnow().date()
    today_queries = AuditLog.query.filter(
        AuditLog.action.in_(["cnpj_query","name_search","socio_search"]),
        AuditLog.created_at >= datetime.combine(today, datetime.min.time())
    ).count()
    total_saved   = SavedCompany.query.count()
    total_inv     = Investigation.query.count()
    return jsonify({"status":"ok","data":{
        "total_users":    total_users,
        "active_users":   active_users,
        "locked_users":   locked_users,
        "total_queries":  total_queries,
        "today_queries":  today_queries,
        "total_saved":    total_saved,
        "total_investigations": total_inv,
    }})


@app.route("/api/admin/cache/clear", methods=["POST"])
def admin_clear_cache():
    _, err = _admin_required()
    if err: return err
    _cnpj_cache.clear()
    _search_cache.clear()
    _socio_cache.clear()
    _audit("admin_cache_clear")
    return jsonify({"status":"ok","message":"Cache limpo"})


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):  return _err("Recurso não encontrado", 404)

@app.errorhandler(429)
def too_many(e):   return _err("Muitas requisições. Aguarde.", 429)

@app.errorhandler(500)
def server_err(e):
    log.error("internal_error", error=str(e))
    return _err("Erro interno do servidor", 500)

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    host = "127.0.0.1" if IS_PROD else "0.0.0.0"
    app.run(host=host, port=5000, debug=not IS_PROD)