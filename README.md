# DKing Intel v3.0 — Plataforma de Inteligência Corporativa

Sistema completo para consulta, cruzamento e análise de dados sobre empresas brasileiras.

---

## 🚀 Instalação Rápida

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Configurar ambiente
cp _env.example .env
# Edite o .env com seus valores

# 3. Iniciar o servidor
python app.py
```

Acesse: http://localhost:5000  
Login padrão: `admin` / `Admin@1234`

---

## ✨ Funcionalidades v3.0

### 🔍 Consulta de Empresas
- Busca por CNPJ com fallback automático entre 4 APIs:
  - **publica.cnpj.ws** (principal, dados ricos + sócios detalhados)
  - **open.cnpja.com** (dados complementares)
  - **brasilapi.com.br** (fallback)
  - **receitaws.com.br** (fallback)
- Visualização completa: dados cadastrais, endereço, QSA, atividades CNAE
- Busca por nome da empresa

### 🏢 Mapeamento de Filiais
- Carrega automaticamente todas as filiais via CNPJ raiz
- Links diretos para consultar cada filial

### 👥 Quadro Societário (QSA)
- Visualiza todos os sócios com qualificação e data de entrada
- CPF/CNPJ dos sócios quando disponível
- Atalho para investigar vínculos do sócio

### 📊 Cruzamento de Dados
- Analisa até 10 CNPJs simultaneamente
- **Detecta automaticamente sócios em comum** entre empresas
- Identifica ramificações e relações ocultas entre empresas

### 🔗 Busca por Sócio
- Encontra todas as empresas vinculadas a um sócio pelo nome
- Útil para mapear holdings e grupos empresariais

### 🌐 Inteligência Digital
- Gera automaticamente 14+ links de pesquisa:
  - LinkedIn (empresa, busca, pessoas)
  - Instagram, Facebook, Twitter/X, TikTok, YouTube
  - Google (geral, social, notícias)
  - Reclame Aqui, Glassdoor, Indeed
  - Escavador, JusBrasil

### 📁 Investigações
- Agrupa CNPJs relacionados em investigações temáticas
- Inicia cruzamento direto de uma investigação

### 💾 Empresas Salvas
- Salva empresas com notas e tags personalizadas
- Acesso rápido para recruzar dados

### 📋 Histórico
- Registro de todas as buscas realizadas
- Rápido reacesso a consultas anteriores

---

## 🔒 Segurança

- **Autenticação por sessão** com cookies HttpOnly
- **Rate limiting** por IP (Flask-Limiter)
- **Bcrypt** com rounds configuráveis (padrão: 12)
- **Bloqueio de conta** após tentativas falhas
- **Sanitização de inputs** com bleach
- **Audit log** completo de todas as ações
- **Headers de segurança** via Flask-Talisman (CSP, HSTS, X-Frame-Options)
- **CORS** restrito às origens configuradas

---

## 🏗️ Estrutura

```
dking-intel/
├── app.py              ← Aplicação principal (Flask)
├── requirements.txt
├── reset_db.py
├── _env.example        ← Template de configuração
└── templates/
    ├── login.html      ← Tela de autenticação
    ├── index.html      ← Dashboard principal
    └── admin.html      ← Painel administrativo
```

---

## 🔧 APIs Utilizadas

| API | URL | Auth | Dados Extras |
|-----|-----|------|--------------|
| cnpj.ws | `publica.cnpj.ws/cnpj/{cnpj}` | Não | Sócios, filiais, Simples |
| cnpja.com | `open.cnpja.com/office/{cnpj}` | Não | Membros detalhados |
| BrasilAPI | `brasilapi.com.br/api/cnpj/v1/` | Não | QSA, CNAEs |
| ReceitaWS | `receitaws.com.br/v1/cnpj/` | Não | Dados básicos |

---

## 👤 Usuários e Papéis

| Papel | Permissões |
|-------|-----------|
| `admin` | Tudo + gestão de usuários + auditoria |
| `operator` | Consultas + salvar empresas |
| `user` | Apenas consultas básicas |

---

## 🚀 Produção

1. Configure `FLASK_ENV=production` no `.env`
2. Defina `SECRET_KEY` e `JWT_SECRET_KEY` com valores fortes
3. Use PostgreSQL: configure `DATABASE_URL`
4. Configure HTTPS e defina `FORCE_HTTPS=True`
5. Use gunicorn: `gunicorn -w 4 app:app`