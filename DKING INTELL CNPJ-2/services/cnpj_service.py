import re
import time
import json
import hashlib
import http.client
import os
import structlog
from pydantic import BaseModel, validator
from typing import Optional
from cachetools import TTLCache

log = structlog.get_logger()

# ─── In-memory cache (TTL = 10 min) ─────────────────────────────────────────
_cache: TTLCache = TTLCache(maxsize=512, ttl=600)


# ─── Response schema validation ─────────────────────────────────────────────

class CNPJResponse(BaseModel):
    cnpj: Optional[str] = None
    nome: Optional[str] = None
    fantasia: Optional[str] = None
    situacao: Optional[str] = None
    abertura: Optional[str] = None
    natureza_juridica: Optional[str] = None
    capital_social: Optional[str] = None
    porte: Optional[str] = None
    logradouro: Optional[str] = None
    numero: Optional[str] = None
    complemento: Optional[str] = None
    bairro: Optional[str] = None
    municipio: Optional[str] = None
    uf: Optional[str] = None
    cep: Optional[str] = None
    email: Optional[str] = None
    telefone: Optional[str] = None
    efr: Optional[str] = None
    qsa: Optional[list] = []
    atividade_principal: Optional[list] = []
    atividades_secundarias: Optional[list] = []

    @validator("cnpj", pre=True, always=True)
    def sanitize_cnpj(cls, v):
        if v:
            return re.sub(r"\D", "", str(v))[:20]
        return v

    @validator("nome", "fantasia", "situacao", "abertura", "natureza_juridica",
               "porte", "logradouro", "numero", "bairro", "municipio", "uf",
               "cep", "telefone", "efr", "complemento", pre=True, always=True)
    def sanitize_str(cls, v):
        if v and isinstance(v, str):
            return v.strip()[:512]
        return v

    @validator("email", pre=True, always=True)
    def sanitize_email(cls, v):
        if v and isinstance(v, str):
            clean = v.strip().lower()[:128]
            return clean if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean) else None
        return None

    class Config:
        extra = "ignore"


# ─── HTTP helper with timeout ────────────────────────────────────────────────

def _https_get(host: str, path: str, timeout: int = 8) -> dict:
    conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        res = conn.getresponse()
        if res.status == 429:
            raise Exception(f"Rate limited by {host}")
        if res.status != 200:
            raise Exception(f"HTTP {res.status}")
        raw = res.read().decode("utf-8")
        data = json.loads(raw)
        if not data:
            raise Exception("Empty response")
        return data
    finally:
        conn.close()


# ─── Individual API fetchers ─────────────────────────────────────────────────

def _api1_receitaws(cnpj: str) -> dict:
    return _https_get("receitaws.com.br", f"/v1/cnpj/{cnpj}")


def _api2_invertexto(cnpj: str) -> dict:
    token = os.environ.get("INVERTEXTO_TOKEN", "")
    return _https_get("api.invertexto.com", f"/v1/cnpj/{cnpj}?token={token}")


def _api3_brasilapi(cnpj: str) -> dict:
    data = _https_get("brasilapi.com.br", f"/api/cnpj/v1/{cnpj}")
    # BrasilAPI uses different field names — normalize here
    mapped = {
        "cnpj": data.get("cnpj"),
        "nome": data.get("razao_social"),
        "fantasia": data.get("nome_fantasia"),
        "situacao": data.get("descricao_situacao_cadastral"),
        "abertura": data.get("data_inicio_atividade"),
        "natureza_juridica": data.get("natureza_juridica", {}).get("descricao") if isinstance(data.get("natureza_juridica"), dict) else data.get("natureza_juridica"),
        "capital_social": str(data.get("capital_social", "")),
        "porte": data.get("porte"),
        "logradouro": data.get("logradouro"),
        "numero": data.get("numero"),
        "complemento": data.get("complemento"),
        "bairro": data.get("bairro"),
        "municipio": data.get("municipio"),
        "uf": data.get("uf"),
        "cep": data.get("cep"),
        "email": data.get("email"),
        "telefone": data.get("ddd_telefone_1"),
        "qsa": [{"nome": s.get("nome_socio", ""), "qual": s.get("qualificacao_socio", "")} for s in data.get("qsa", [])],
        "atividade_principal": [{"code": data.get("cnae_fiscal", ""), "text": data.get("cnae_fiscal_descricao", "")}],
        "atividades_secundarias": [{"code": a.get("codigo", ""), "text": a.get("descricao", "")} for a in data.get("cnaes_secundarios", [])],
    }
    return mapped


# ─── Retry wrapper ───────────────────────────────────────────────────────────

def _fetch_with_retry(fetcher, cnpj: str, retries: int = 2, delay: float = 0.5) -> dict:
    last_error = None
    for attempt in range(retries + 1):
        try:
            return fetcher(cnpj)
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(delay * (attempt + 1))
    raise last_error


# ─── Main service ─────────────────────────────────────────────────────────────

class CNPJServiceError(Exception):
    pass


def consultar_cnpj(cnpj: str) -> dict:
    cnpj = re.sub(r"\D", "", cnpj)
    if not re.fullmatch(r"\d{14}", cnpj) or len(set(cnpj)) == 1:
        raise ValueError("CNPJ inválido")

    # Cache check
    cache_key = hashlib.md5(cnpj.encode()).hexdigest()
    if cache_key in _cache:
        log.info("cnpj_cache_hit", cnpj=cnpj[:8] + "******")
        return _cache[cache_key]

    apis = [
        ("receitaws", _api1_receitaws),
        ("invertexto", _api2_invertexto),
        ("brasilapi", _api3_brasilapi),
    ]

    errors = []
    for name, fetcher in apis:
        try:
            raw = _fetch_with_retry(fetcher, cnpj)
            validated = CNPJResponse(**raw).dict()
            result = {"padrao": {"cnpj": validated["cnpj"], "nome": validated["nome"]}, "raw": validated}
            _cache[cache_key] = result
            log.info("cnpj_fetched", source=name, cnpj=cnpj[:8] + "******")
            return result
        except Exception as exc:
            log.warning("cnpj_api_failed", api=name, error=str(exc))
            errors.append(f"{name}: {exc}")

    raise CNPJServiceError(f"Todas as APIs falharam: {errors}")


def invalidate_cache(cnpj: str):
    key = hashlib.md5(re.sub(r"\D", "", cnpj).encode()).hexdigest()
    _cache.pop(key, None)
