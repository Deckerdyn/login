from fastapi import FastAPI, Depends, HTTPException, status, Request, Header, Form
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from app.database.db import db  
from app.models.user import UserCreate, UserResponse  
from app.auth.hash import hash_password, verify_password  
from app.auth.jwt import create_access_token, verify_token  
import os
from bson import ObjectId
from app.database.db import users_collection, meditions_collection  
from datetime import datetime, timedelta, timezone
import jwt
from app.auth.jwt import SECRET_KEY, ALGORITHM  
from app.auth.roles import roles  
import pytz
from decouple import config
import secrets 
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import logging

# Zona horaria de Chile
chile_tz = pytz.timezone("America/Santiago")
app = FastAPI()

# (Las credenciales de CLIENT_ID y CLIENT_SECRET ya no se usarán)
# CLIENT_ID = config("CLIENT_ID")
# CLIENT_SECRET = config("CLIENT_SECRET")

# Se eliminan las funciones get_token, fetch_data_from_api, save_data y el scheduler,
# ya que ahora únicamente se leen los datos desde la base de datos.

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Middleware CSP para mejorar la seguridad
class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        if request.url.path.startswith("/docs") or request.url.path.startswith("/redoc"):
            return response
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https:; "
            "style-src 'self' 'unsafe-inline' https:; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https:; "
            "connect-src 'self' https:; "
            "object-src 'none'; "
            "frame-src 'none'; "
            "base-uri 'self';"
        )
        return response

app.add_middleware(CSPMiddleware)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Servir archivos estáticos desde "frontend/static"
app.mount("/static", StaticFiles(directory=os.path.join(os.getcwd(), "frontend/static")), name="static")

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simula un almacenamiento en memoria para las consultas realizadas
query_logs = {}

# Diccionario en memoria para registrar intentos fallidos
failed_login_attempts = {}
MAX_ATTEMPTS = 3  
BLOCK_TIME = timedelta(minutes=1)

# Función para generar un token CSRF seguro
def generate_csrf_token():
    return secrets.token_urlsafe(32)

@app.get("/csrf-token")
async def get_csrf_token(request: Request):
    if not request.cookies.get("access_token"):
        raise HTTPException(status_code=401, detail="No autenticado")
    csrf_token = request.cookies.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_hex(16)
    response = JSONResponse({"csrf_token": csrf_token})
    response.set_cookie("csrf_token", csrf_token, httponly=True, secure=True, samesite="Strict", max_age=timedelta(hours=24))
    return response

def track_user_queries(user_email: str, max_queries: int):
    now = datetime.now(timezone.utc).date().isoformat()
    user = db.users.find_one({"email": user_email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    query_logs = user.get("query_logs", {})
    current_count = query_logs.get(now, 0)
    if max_queries is not None and current_count >= max_queries:
        raise HTTPException(status_code=403, detail="Limite de consultas excedido")
    query_logs[now] = current_count + 1
    db.users.update_one({"email": user_email}, {"$set": {"query_logs": query_logs}})

@app.get("/protected-resource")
def protected_resource(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha caducado")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail="Token no válido")
    role = payload.get("role")
    email = payload.get("sub")
    if not role or not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no válido")
    return {"message": f"Acceso concedido a {email}"}

@app.get("/protegido", response_class=HTMLResponse)
async def get_protegido(request: Request):
    with open("frontend/protegido.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

@app.get("/")
async def get_index():
    with open("frontend/index.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

def role_required(required_role: str):
    def role_checker(token: dict = Depends(verify_token)):
        if token["role"] != required_role:
            raise HTTPException(status_code=403, detail="Permisos insuficientes")
        return token
    return role_checker

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    with open("frontend/dashboard.html", encoding="utf-8") as file:
        content = file.read()
    return HTMLResponse(content=content, status_code=200)

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate):
    existing_user = db.users.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Correo electrónico ya registrado")
    hashed_password = hash_password(user.password)
    if not user.role:
        user.role = 'usuario'
    user_data = {
        "email": user.email,
        "password": hashed_password,
        "role": user.role,
        "query_logs": {}
    }
    user_id = db.users.insert_one(user_data).inserted_id
    return {"id": str(user_id), "email": user.email, "role": user.role}

@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...), response: Response = None):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="Credenciales no válidas")
    if not verify_password(password, user["password"]):
        raise HTTPException(status_code=400, detail="Credenciales no válidas")
    role = user.get("role", "temporary_user")
    access_token = create_access_token(data={"sub": user["email"], "role": role}, role=role)
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  
        max_age=timedelta(hours=24),
        secure=False  
    )
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        samesite="Strict",
        secure=False  
    )
    return {"csrf_token": csrf_token, "message": "Inicio de sesión exitoso"}

async def verify_csrf_token(request: Request, csrf_token: str = Header(None)):
    stored_csrf_token = request.cookies.get("csrf_token")
    if not stored_csrf_token or stored_csrf_token != csrf_token:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

@app.post("/protected-action", dependencies=[Depends(verify_csrf_token)])
async def protected_action():
    return {"message": "Token CSRF validado exitosamente"}

@app.post("/generate-token")
async def generate_token(email: str, role: str):
    role_config = roles.get(role)
    if not role_config:
        raise HTTPException(status_code=400, detail=f"El rol '{role}' no está configurado")
    user = db["users"].find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    token = create_access_token(
        data={"sub": email, "role": role},
        role=role
    )
    return JSONResponse(content={"access_token": token, "token_type": "bearer"})

@app.get("/protected")
async def protected_route(request: Request):
    csrf_token_from_cookie = request.cookies.get("csrf_token")
    if not csrf_token_from_cookie:
        raise HTTPException(status_code=401, detail="Falta el token CSRF")
    csrf_token_from_header = request.headers.get("X-CSRF-Token")
    if not csrf_token_from_header:
        raise HTTPException(status_code=401, detail="Falta el token CSRF en la solicitud")
    if csrf_token_from_cookie != csrf_token_from_header:
        raise HTTPException(status_code=403, detail="Token CSRF no válido")
    token_from_cookie = request.cookies.get("access_token")
    if not token_from_cookie:
        raise HTTPException(status_code=401, detail="Falta el token de acceso")
    try:
        token = verify_token(token_from_cookie)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Token no válido")
    email = token.get("sub")
    role = token.get("role")
    exp = token.get("exp")
    iat = token.get("iat")
    if not email or not role or not exp:
        raise HTTPException(status_code=401, detail="Datos de token no válidos")
    role_data = roles.get(role)
    if not role_data:
        raise HTTPException(status_code=403, detail="Rol no encontrado")
    max_queries = role_data.get("max_queries")
    token_duration = role_data.get("token_duration")
    access_schedule = role_data.get("access_schedule")
    now_chile = datetime.now(chile_tz)
    if iat is not None and token_duration is not None:
        issued_at = datetime.fromtimestamp(iat, timezone.utc).astimezone(chile_tz)
        token_lifetime = timedelta(minutes=token_duration)
        if now_chile > issued_at + token_lifetime:
            raise HTTPException(status_code=401, detail="Se superó la duración del token")
    token_expiration = datetime.fromtimestamp(exp, timezone.utc).astimezone(chile_tz)
    if now_chile > token_expiration:
        raise HTTPException(status_code=401, detail="El token ha caducado")
    if access_schedule:
        current_hour = now_chile.hour
        if not (access_schedule["start"] <= current_hour < access_schedule["end"]):
            raise HTTPException(status_code=403, detail="Acceso no permitido fuera del horario previsto")
    track_user_queries(email, max_queries)
    return {"message": f"Acceso concedido a {email}", "role": role}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("csrf_token", path="/")
    return {"message": "Cerró sesión exitosamente"}

@app.put("/update_user/{user_id}", response_model=UserResponse)
def update_user(user_id: str, user: UserCreate):
    db_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    updated_data = {}
    if user.email:
        updated_data["email"] = user.email
    if user.password:
        updated_data["password"] = hash_password(user.password)
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": updated_data})
    return {"id": user_id, "email": user.email}

@app.delete("/delete_user/{user_id}", response_model=UserResponse)
def delete_user(user_id: str):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.users.delete_one({"_id": ObjectId(user_id)})
    return {"id": user_id, "email": user["email"]}

# Endpoint para obtener los datos almacenados (solo lectura)
@app.get("/datos")
def get_datos():
    latest_mediciones = list(meditions_collection.find().sort("ultima_actualizacion", -1))
    for doc in latest_mediciones:
        doc["_id"] = str(doc["_id"])
    return {
        "status": "success",
        "mediciones": latest_mediciones,
        "ultimo_dato": datetime.utcnow(),
        "url": "http://10.10.8.60:3001/datos"
    }
