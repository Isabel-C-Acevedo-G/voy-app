# instalar.ps1
# Ejecuta este script UNA sola vez desde la raiz de tu proyecto (c:\parqueadero-bicicletas)
# Crea/reemplaza los 13 archivos del proyecto con el contenido actualizado.
Write-Host "Instalando archivos del proyecto voy. ..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
"""
Sistema Web para la Gestión de Parqueaderos de Bicicletas - Medellín
Capa de Presentación / Controller (patrón MVC).

Arquitectura por capas:
  Presentación   -> este archivo (endpoints FastAPI)
  Lógica         -> validaciones de reglas de negocio (RN-01 a RN-09) en
                    cada endpoint, apoyadas en dao.py y patterns.py
  Acceso a Datos -> database.py + dao.py
  Base de Datos  -> MySQL (ParqueaderoBicicletas)

Patrones aplicados: MVC (este archivo + schemas.py + frontend),
Singleton (database.py), DAO/Repository (dao.py), Factory, Strategy y
Observer (patterns.py).
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from dao import BicicletaDAO, EspacioDAO, IncidenteDAO, MovimientoDAO, ReservaDAO, UsuarioDAO
from patterns import UsuarioFactory, notificador, obtener_estrategia
from schemas import (
    Credenciales,
    DisponibilidadResponse,
    FiltroReporte,
    IncidenteRequest,
    IngresoRequest,
    LoginResponse,
    RegistroBicicleta,
    RegistroUsuario,
    ReservaRequest,
    SalidaRequest,
)
from security import crear_token, obtener_usuario_actual, requerir_roles, verify_password

RESERVA_CHECK_INTERVALO_SEGUNDOS = 60


# ---------------------------------------------------------------------------
# Tarea en segundo plano: caducidad automática de reservas (RN-05)
# ---------------------------------------------------------------------------
async def _expirar_reservas_periodicamente():
    while True:
        try:
            expiradas = ReservaDAO.listar_activas_expiradas()
            for reserva in expiradas:
                ReservaDAO.marcar_estado(reserva["IdReserva"], "Expirada")
                EspacioDAO.actualizar_estado(reserva["IdEspacio"], "Disponible")
                notificador.notificar(
                    "reserva_expirada",
                    {"id_reserva": reserva["IdReserva"], "id_espacio": reserva["IdEspacio"]},
                )
        except Exception as e:
            print(f"[expirar_reservas] error: {e}")
        await asyncio.sleep(RESERVA_CHECK_INTERVALO_SEGUNDOS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    tarea = asyncio.create_task(_expirar_reservas_periodicamente())
    yield
    tarea.cancel()


app = FastAPI(title="voy. - Sistema de Parqueaderos de Bicicletas (Medellín)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# RF-01 / RF-02: Registro y autenticación
# ---------------------------------------------------------------------------
@app.post("/register")
def registrar_usuario(usuario: RegistroUsuario):
    if UsuarioDAO.existe_por_documento_o_correo(usuario.documento, usuario.correo):
        raise HTTPException(status_code=400, detail="El documento o correo ya está registrado.")

    payload = UsuarioFactory.crear_payload(
        usuario.documento,
        usuario.nombres,
        usuario.apellidos,
        usuario.correo,
        usuario.telefono,
        usuario.contrasena,
        usuario.rol,
    )
    id_rol = UsuarioDAO.obtener_id_rol(payload["rol"])
    if id_rol is None:
        raise HTTPException(status_code=400, detail=f"El rol '{payload['rol']}' no existe en el sistema.")

    UsuarioDAO.crear(
        payload["documento"],
        payload["nombres"],
        payload["apellidos"],
        payload["correo"],
        payload["telefono"],
        payload["password_hash"],
        id_rol,
    )
    return {"status": "success", "mensaje": "Usuario registrado correctamente. Ya puedes iniciar sesión."}


@app.post("/login", response_model=LoginResponse)
def iniciar_sesion(credenciales: Credenciales):
    resultado = UsuarioDAO.buscar_para_login(credenciales.usuario)

    if not resultado or not verify_password(credenciales.contrasena, resultado["PasswordHash"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")

    if resultado["Estado"] != "Activo":
        # RN-08: usuarios desactivados no pueden iniciar sesión.
        raise HTTPException(status_code=403, detail="Esta cuenta está desactivada. Contacte al administrador.")

    token = crear_token(resultado["Documento"], resultado["NombreRol"], resultado["IdUsuario"])
    return LoginResponse(
        status="success",
        mensaje="Acceso verificado.",
        token=token,
        rol=resultado["NombreRol"],
        nombres=resultado["Nombres"],
        documento=resultado["Documento"],
        expira_minutos=30,
    )


# ---------------------------------------------------------------------------
# RF-03: Registro de bicicletas (necesario para poder operar ingresos)
# ---------------------------------------------------------------------------
@app.post("/bicicletas/registrar")
def registrar_bicicleta(
    bici: RegistroBicicleta, usuario_actual: dict = Depends(obtener_usuario_actual)
):
    if BicicletaDAO.existe_numero_serie(bici.numero_serie):
        # RN-01: número de serie único.
        raise HTTPException(status_code=400, detail="Ya existe una bicicleta registrada con ese número de serie.")

    propietario = UsuarioDAO.buscar_por_documento(usuario_actual["documento"])
    if propietario is None:
        raise HTTPException(status_code=404, detail="Usuario propietario no encontrado.")

    id_bicicleta = BicicletaDAO.crear(
        propietario["IdUsuario"], bici.marca, bici.modelo, bici.color, bici.numero_serie, bici.foto
    )
    return {"status": "success", "mensaje": "Bicicleta registrada.", "id_bicicleta": id_bicicleta}


@app.get("/bicicletas/mias")
def mis_bicicletas(usuario_actual: dict = Depends(obtener_usuario_actual)):
    propietario = UsuarioDAO.buscar_por_documento(usuario_actual["documento"])
    if propietario is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    return {"bicicletas": BicicletaDAO.listar_por_usuario(propietario["IdUsuario"])}


# ---------------------------------------------------------------------------
# RF-06: Disponibilidad de cupos en tiempo real (público, sin autenticación)
# ---------------------------------------------------------------------------
@app.get("/disponibilidad", response_model=DisponibilidadResponse)
def consultar_disponibilidad():
    conteo = EspacioDAO.contar_por_estado()
    total = conteo["Disponible"] + conteo["Ocupado"] + conteo["Reservado"]
    return DisponibilidadResponse(
        libres=conteo["Disponible"], ocupados=conteo["Ocupado"], reservados=conteo["Reservado"], total=total
    )


# Alias retrocompatible con el frontend original (GET /cupos)
@app.get("/cupos")
def cupos_disponibles_legacy():
    conteo = EspacioDAO.contar_por_estado()
    return {"cupos_libres": conteo["Disponible"]}


# ---------------------------------------------------------------------------
# RF-04 / RN-02 / RN-04: Registrar ingreso (Vigilante, Administrador)
# ---------------------------------------------------------------------------
@app.post("/ingresos/registrar")
def registrar_ingreso(
    ingreso: IngresoRequest,
    usuario_actual: dict = Depends(requerir_roles("Vigilante", "Administrador")),
):
    propietario = UsuarioDAO.buscar_por_documento(ingreso.documento)
    if propietario is None:
        raise HTTPException(status_code=404, detail="No existe un usuario registrado con ese documento.")

    # Selección de la bicicleta a ingresar.
    bicicletas = BicicletaDAO.listar_por_usuario(propietario["IdUsuario"])
    if not bicicletas:
        raise HTTPException(status_code=404, detail="El usuario no tiene bicicletas registradas.")

    if ingreso.id_bicicleta:
        bicicleta = next((b for b in bicicletas if b["IdBicicleta"] == ingreso.id_bicicleta), None)
        if bicicleta is None:
            raise HTTPException(status_code=404, detail="La bicicleta indicada no pertenece a este usuario.")
    elif len(bicicletas) == 1:
        bicicleta = bicicletas[0]
    else:
        raise HTTPException(
            status_code=400,
            detail="El usuario tiene varias bicicletas registradas; especifique id_bicicleta.",
        )

    # RN-02: la bicicleta no debe tener ya un ingreso activo.
    if MovimientoDAO.ingreso_activo_de_bicicleta(bicicleta["IdBicicleta"]):
        raise HTTPException(status_code=400, detail="Esta bicicleta ya se encuentra en el parqueadero.")

    # CU-03 paso 6: si el usuario tiene una reserva activa, se convierte en ingreso (RN-06).
    reserva_activa = ReservaDAO.reserva_activa_de_usuario(propietario["IdUsuario"])
    if reserva_activa:
        espacio = EspacioDAO.obtener_por_id(reserva_activa["IdEspacio"])
        ReservaDAO.marcar_estado(reserva_activa["IdReserva"], "Convertida")
    else:
        # RN-04: solo se permite el ingreso si hay cupos disponibles.
        espacio = EspacioDAO.primero_disponible()
        if espacio is None:
            raise HTTPException(status_code=400, detail="Parqueadero lleno. No hay cupos disponibles.")

    id_ingreso = MovimientoDAO.crear_ingreso(bicicleta["IdBicicleta"], propietario["IdUsuario"], espacio["IdEspacio"])
    EspacioDAO.actualizar_estado(espacio["IdEspacio"], "Ocupado")

    notificador.notificar("ingreso_registrado", {"id_ingreso": id_ingreso, "id_espacio": espacio["IdEspacio"]})

    return {
        "status": "success",
        "mensaje": f"Ingreso registrado para {ingreso.documento} en el espacio {espacio['CodigoEspacio']}.",
        "id_ingreso": id_ingreso,
        "espacio": espacio["CodigoEspacio"],
        "fecha": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# RF-05 / RN-03: Registrar salida (Vigilante, Administrador)
# ---------------------------------------------------------------------------
@app.post("/salidas/registrar")
def registrar_salida(
    salida: SalidaRequest,
    usuario_actual: dict = Depends(requerir_roles("Vigilante", "Administrador")),
):
    propietario = UsuarioDAO.buscar_por_documento(salida.documento)
    if propietario is None:
        raise HTTPException(status_code=404, detail="No existe un usuario registrado con ese documento.")

    activos = MovimientoDAO.ingresos_activos_de_usuario(propietario["IdUsuario"])
    if not activos:
        # RN-03
        raise HTTPException(status_code=404, detail="No se encontró ingreso activo para este usuario.")

    if salida.id_bicicleta:
        ingreso = next((i for i in activos if i["IdBicicleta"] == salida.id_bicicleta), None)
        if ingreso is None:
            raise HTTPException(status_code=404, detail="No hay ingreso activo para esa bicicleta.")
    elif len(activos) == 1:
        ingreso = activos[0]
    else:
        raise HTTPException(
            status_code=400,
            detail="El usuario tiene varios ingresos activos; especifique id_bicicleta.",
        )

    MovimientoDAO.crear_salida(ingreso["IdIngreso"])
    EspacioDAO.actualizar_estado(ingreso["IdEspacio"], "Disponible")

    notificador.notificar("salida_registrada", {"id_ingreso": ingreso["IdIngreso"], "id_espacio": ingreso["IdEspacio"]})

    return {
        "status": "success",
        "mensaje": f"Salida registrada para {salida.documento} desde el espacio {ingreso['CodigoEspacio']}.",
        "espacio": ingreso["CodigoEspacio"],
        "fecha": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# RF-07 / RN-05 / RN-06: Reservas anticipadas (rol Usuario)
# ---------------------------------------------------------------------------
@app.post("/reservas/crear")
def crear_reserva(
    reserva: ReservaRequest, usuario_actual: dict = Depends(requerir_roles("Usuario"))
):
    propietario = UsuarioDAO.buscar_por_documento(usuario_actual["documento"])
    if propietario is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    if ReservaDAO.reserva_activa_de_usuario(propietario["IdUsuario"]):
        raise HTTPException(status_code=400, detail="Ya tienes una reserva activa. Espera a que se use o expire.")

    bicicletas = BicicletaDAO.listar_por_usuario(propietario["IdUsuario"])
    if not bicicletas:
        raise HTTPException(status_code=404, detail="Debes registrar al menos una bicicleta antes de reservar.")

    if reserva.id_bicicleta:
        bicicleta = next((b for b in bicicletas if b["IdBicicleta"] == reserva.id_bicicleta), None)
        if bicicleta is None:
            raise HTTPException(status_code=404, detail="Esa bicicleta no te pertenece.")
    else:
        bicicleta = bicicletas[0]

    espacio = EspacioDAO.primero_disponible()
    if espacio is None:
        raise HTTPException(status_code=400, detail="No hay cupos disponibles para reserva.")

    datos_reserva = ReservaDAO.crear(propietario["IdUsuario"], bicicleta["IdBicicleta"], espacio["IdEspacio"])
    EspacioDAO.actualizar_estado(espacio["IdEspacio"], "Reservado")

    notificador.notificar(
        "reserva_creada", {"id_reserva": datos_reserva["id_reserva"], "id_espacio": espacio["IdEspacio"]}
    )

    return {
        "status": "success",
        "mensaje": f"Cupo {espacio['CodigoEspacio']} reservado por 30 minutos.",
        "id_reserva": datos_reserva["id_reserva"],
        "codigo_espacio": espacio["CodigoEspacio"],
        "fecha_expiracion": datos_reserva["fecha_expiracion"].isoformat(),
    }


@app.get("/reservas/mia")
def mi_reserva_activa(usuario_actual: dict = Depends(requerir_roles("Usuario"))):
    propietario = UsuarioDAO.buscar_por_documento(usuario_actual["documento"])
    if propietario is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    reserva = ReservaDAO.reserva_activa_de_usuario(propietario["IdUsuario"])
    return {"reserva": reserva}


# ---------------------------------------------------------------------------
# RF-08: Registro de incidentes (Vigilante, Administrador)
# ---------------------------------------------------------------------------
@app.post("/incidentes/registrar")
def registrar_incidente(
    incidente: IncidenteRequest,
    usuario_actual: dict = Depends(requerir_roles("Vigilante", "Administrador")),
):
    id_usuario = None
    if incidente.documento_usuario:
        propietario = UsuarioDAO.buscar_por_documento(incidente.documento_usuario)
        id_usuario = propietario["IdUsuario"] if propietario else None

    id_incidente = IncidenteDAO.crear(id_usuario, incidente.id_bicicleta, incidente.tipo, incidente.descripcion)

    return {"status": "success", "mensaje": "Incidente registrado correctamente.", "id_incidente": id_incidente}


# ---------------------------------------------------------------------------
# RF-10: Reportes (solo Administrador)
# ---------------------------------------------------------------------------
@app.get("/reportes/generar")
def generar_reporte(
    fecha_inicio: datetime = Query(...),
    fecha_fin: datetime = Query(...),
    tipo: str = Query("movimientos", description="movimientos | incidentes"),
    formato: str = Query("json", description="json | csv | pdf"),
    usuario_actual: dict = Depends(requerir_roles("Administrador")),
):
    if tipo == "incidentes":
        datos = IncidenteDAO.por_rango(fecha_inicio, fecha_fin)
        nombre = "reporte_incidentes"
    else:
        datos = MovimientoDAO.movimientos_por_rango(fecha_inicio, fecha_fin)
        nombre = "reporte_movimientos"

    datos_serializables = [
        {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in fila.items()} for fila in datos
    ]

    estrategia = obtener_estrategia(formato)
    return estrategia.exportar(datos_serializables, nombre)
'@
Set-Content -Path "backend\main.py" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\main.py" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
"""
Capa de Acceso a Datos - Conexión a MySQL.

Patrón de diseño aplicado: SINGLETON.
Una única instancia de pool de conexiones es compartida por toda la
aplicación, evitando la creación de conexiones duplicadas y optimizando
los recursos del servidor (ver sección 13 del ERS - Patrones de Diseño).
"""

import os
from contextlib import contextmanager

from mysql.connector import pooling, Error


class DatabaseConnection:
    """Único punto de acceso al pool de conexiones MySQL (Singleton)."""

    _instance = None
    _pool = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._inicializar_pool()
        return cls._instance

    def _inicializar_pool(self):
        try:
            self._pool = pooling.MySQLConnectionPool(
                pool_name="voy_pool",
                pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
                host=os.getenv("DB_SERVER", "mysql"),
                port=int(os.getenv("DB_PORT", "3306")),
                user=os.getenv("DB_UID", "root"),
                password=os.getenv("DB_PWD", "root"),
                database=os.getenv("DB_DATABASE", "ParqueaderoBicicletas"),
                charset="utf8mb4",
                use_pure=True,
                autocommit=False,
            )
        except Error as e:
            print(f"[DatabaseConnection] Error inicializando el pool MySQL: {e}")
            raise

    def obtener_conexion(self):
        return self._pool.get_connection()


# Instancia única compartida (Singleton) creada en el arranque del módulo.
_db = DatabaseConnection()


@contextmanager
def get_cursor(dictionary: bool = True, commit: bool = False):
    """
    Context manager que entrega un cursor listo para usar y libera la
    conexión automáticamente al finalizar, incluso si ocurre un error.
    """
    conn = _db.obtener_conexion()
    cursor = conn.cursor(dictionary=dictionary)
    try:
        yield cursor
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()
'@
Set-Content -Path "backend\database.py" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\database.py" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
"""
Módulo de seguridad: hashing de contraseñas (bcrypt) y sesiones (JWT).

RF-02: "La sesión expira automáticamente después de 30 minutos de
inactividad." Se implementa mediante un token JWT con expiración corta:
cada nueva petición autenticada exige un token vigente; el frontend debe
volver a solicitar login si el token expiró.

RNF03: Las contraseñas se almacenan encriptadas con bcrypt (passlib),
nunca en texto plano.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

SECRET_KEY = os.getenv("JWT_SECRET", "voy-medellin-cambiar-esta-clave-en-produccion")
ALGORITHM = "HS256"
EXPIRACION_MINUTOS = 30  # RF-02

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Contraseñas
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tokens JWT (sesión)
# ---------------------------------------------------------------------------
def crear_token(documento: str, rol: str, id_usuario: int) -> str:
    expira = datetime.now(timezone.utc) + timedelta(minutes=EXPIRACION_MINUTOS)
    payload = {
        "sub": documento,
        "rol": rol,
        "id_usuario": id_usuario,
        "exp": expira,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _decodificar_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La sesión ha expirado. Inicia sesión nuevamente.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido. Inicia sesión nuevamente.",
        )


def obtener_usuario_actual(
    credenciales: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> dict:
    if credenciales is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado. Debe iniciar sesión.",
        )
    payload = _decodificar_token(credenciales.credentials)
    return {
        "documento": payload.get("sub"),
        "rol": payload.get("rol"),
        "id_usuario": payload.get("id_usuario"),
    }


def requerir_roles(*roles_permitidos: str):
    """Dependencia de FastAPI para restringir un endpoint a ciertos roles (RF-02, RF-09)."""

    def _verificador(usuario: dict = Depends(obtener_usuario_actual)) -> dict:
        if usuario["rol"] not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acceso denegado. Se requiere rol: {', '.join(roles_permitidos)}.",
            )
        return usuario

    return _verificador
'@
Set-Content -Path "backend\security.py" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\security.py" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
"""
Capa de Modelo (MVC) - Esquemas Pydantic para solicitudes y respuestas.
Tipado estricto según lo exigido: cada endpoint valida su entrada aquí.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Autenticación / Usuarios (RF-01, RF-02, RF-09)
# ---------------------------------------------------------------------------
class Credenciales(BaseModel):
    usuario: str = Field(..., description="Correo o documento")
    contrasena: str


class RegistroUsuario(BaseModel):
    documento: str
    nombres: str
    apellidos: str
    correo: EmailStr
    telefono: Optional[str] = None
    contrasena: str = Field(..., min_length=4)
    rol: str = "Usuario"  # Usuario (Ciclista) | Vigilante | Administrador


class LoginResponse(BaseModel):
    status: str
    mensaje: str
    token: str
    rol: str
    nombres: str
    documento: str
    expira_minutos: int


# ---------------------------------------------------------------------------
# Bicicletas (RF-03) - necesarias para que el flujo de ingreso funcione
# ---------------------------------------------------------------------------
class RegistroBicicleta(BaseModel):
    marca: Optional[str] = None
    modelo: Optional[str] = None
    color: Optional[str] = None
    numero_serie: str
    foto: Optional[str] = None  # referencia/nombre de archivo o base64 corto


# ---------------------------------------------------------------------------
# Ingresos / Salidas (RF-04, RF-05, RN-02, RN-03, RN-04)
# ---------------------------------------------------------------------------
class IngresoRequest(BaseModel):
    documento: str
    id_bicicleta: Optional[int] = None


class SalidaRequest(BaseModel):
    documento: str
    id_bicicleta: Optional[int] = None


# ---------------------------------------------------------------------------
# Disponibilidad (RF-06)
# ---------------------------------------------------------------------------
class DisponibilidadResponse(BaseModel):
    libres: int
    ocupados: int
    reservados: int
    total: int


# ---------------------------------------------------------------------------
# Reservas (RF-07, RN-05, RN-06)
# ---------------------------------------------------------------------------
class ReservaRequest(BaseModel):
    id_bicicleta: Optional[int] = None


class ReservaResponse(BaseModel):
    id_reserva: int
    codigo_espacio: str
    fecha_reserva: datetime
    fecha_expiracion: datetime
    estado: str


# ---------------------------------------------------------------------------
# Incidentes (RF-08)
# ---------------------------------------------------------------------------
class IncidenteRequest(BaseModel):
    tipo: str = Field(..., description="daño | sospecha | perdida | otro")
    descripcion: str
    documento_usuario: Optional[str] = None
    id_bicicleta: Optional[int] = None
    foto: Optional[str] = None


# ---------------------------------------------------------------------------
# Reportes (RF-10)
# ---------------------------------------------------------------------------
class FiltroReporte(BaseModel):
    fecha_inicio: datetime
    fecha_fin: datetime
    tipo: str = Field("movimientos", description="movimientos | incidentes | ocupacion")
'@
Set-Content -Path "backend\schemas.py" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\schemas.py" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
"""
Capa de Acceso a Datos (Acceso a Datos en la arquitectura por capas).

Patrón de diseño aplicado: DAO / REPOSITORY.
Cada clase centraliza las operaciones de consulta y persistencia de una
entidad, aislando el SQL del resto de la aplicación (lógica de negocio en
main.py) y facilitando un eventual cambio de motor de base de datos.
"""

from datetime import datetime, timedelta
from typing import Optional

from database import get_cursor

RESERVA_MINUTOS_VALIDEZ = 30  # RN-05, RN-06


class UsuarioDAO:
    @staticmethod
    def existe_por_documento_o_correo(documento: str, correo: str) -> bool:
        with get_cursor() as cur:
            cur.execute(
                "SELECT IdUsuario FROM Usuarios WHERE Documento = %s OR Correo = %s",
                (documento, correo),
            )
            return cur.fetchone() is not None

    @staticmethod
    def crear(documento, nombres, apellidos, correo, telefono, password_hash, id_rol) -> int:
        with get_cursor(commit=True) as cur:
            cur.execute(
                """INSERT INTO Usuarios
                   (Documento, Nombres, Apellidos, Correo, Telefono, PasswordHash, IdRol)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (documento, nombres, apellidos, correo, telefono, password_hash, id_rol),
            )
            return cur.lastrowid

    @staticmethod
    def buscar_para_login(usuario: str) -> Optional[dict]:
        with get_cursor() as cur:
            cur.execute(
                """SELECT U.IdUsuario, U.Documento, U.Nombres, U.PasswordHash,
                          U.Estado, R.NombreRol
                   FROM Usuarios U
                   INNER JOIN Roles R ON U.IdRol = R.IdRol
                   WHERE U.Correo = %s OR U.Documento = %s""",
                (usuario, usuario),
            )
            return cur.fetchone()

    @staticmethod
    def buscar_por_documento(documento: str) -> Optional[dict]:
        with get_cursor() as cur:
            cur.execute(
                """SELECT U.IdUsuario, U.Documento, U.Nombres, U.Apellidos, U.Estado, R.NombreRol
                   FROM Usuarios U
                   INNER JOIN Roles R ON U.IdRol = R.IdRol
                   WHERE U.Documento = %s""",
                (documento,),
            )
            return cur.fetchone()

    @staticmethod
    def obtener_id_rol(nombre_rol: str) -> Optional[int]:
        with get_cursor() as cur:
            cur.execute("SELECT IdRol FROM Roles WHERE NombreRol = %s", (nombre_rol,))
            fila = cur.fetchone()
            return fila["IdRol"] if fila else None


class BicicletaDAO:
    @staticmethod
    def crear(id_usuario, marca, modelo, color, numero_serie, foto) -> int:
        with get_cursor(commit=True) as cur:
            cur.execute(
                """INSERT INTO Bicicletas (IdUsuario, Marca, Modelo, Color, NumeroSerie, Foto)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (id_usuario, marca, modelo, color, numero_serie, foto),
            )
            return cur.lastrowid

    @staticmethod
    def existe_numero_serie(numero_serie: str) -> bool:
        with get_cursor() as cur:
            cur.execute("SELECT IdBicicleta FROM Bicicletas WHERE NumeroSerie = %s", (numero_serie,))
            return cur.fetchone() is not None

    @staticmethod
    def listar_por_usuario(id_usuario: int) -> list:
        with get_cursor() as cur:
            cur.execute(
                "SELECT * FROM Bicicletas WHERE IdUsuario = %s AND Estado = 'Activa'",
                (id_usuario,),
            )
            return cur.fetchall()

    @staticmethod
    def obtener_por_id(id_bicicleta: int) -> Optional[dict]:
        with get_cursor() as cur:
            cur.execute("SELECT * FROM Bicicletas WHERE IdBicicleta = %s", (id_bicicleta,))
            return cur.fetchone()


class EspacioDAO:
    @staticmethod
    def contar_por_estado() -> dict:
        with get_cursor() as cur:
            cur.execute("SELECT Estado, COUNT(*) AS total FROM Espacios GROUP BY Estado")
            filas = cur.fetchall()
            conteo = {"Disponible": 0, "Ocupado": 0, "Reservado": 0}
            for f in filas:
                conteo[f["Estado"]] = f["total"]
            return conteo

    @staticmethod
    def primero_disponible() -> Optional[dict]:
        with get_cursor() as cur:
            cur.execute(
                "SELECT * FROM Espacios WHERE Estado = 'Disponible' ORDER BY IdEspacio LIMIT 1"
            )
            return cur.fetchone()

    @staticmethod
    def actualizar_estado(id_espacio: int, estado: str):
        with get_cursor(commit=True) as cur:
            cur.execute(
                "UPDATE Espacios SET Estado = %s WHERE IdEspacio = %s", (estado, id_espacio)
            )

    @staticmethod
    def obtener_por_id(id_espacio: int) -> Optional[dict]:
        with get_cursor() as cur:
            cur.execute("SELECT * FROM Espacios WHERE IdEspacio = %s", (id_espacio,))
            return cur.fetchone()


class MovimientoDAO:
    """Gestiona Ingresos y Salidas (clase 'Movimiento' del diagrama UML)."""

    @staticmethod
    def ingreso_activo_de_bicicleta(id_bicicleta: int) -> Optional[dict]:
        """RN-02: una bicicleta no puede tener dos ingresos activos simultáneos."""
        with get_cursor() as cur:
            cur.execute(
                """SELECT I.* FROM Ingresos I
                   LEFT JOIN Salidas S ON S.IdIngreso = I.IdIngreso
                   WHERE I.IdBicicleta = %s AND S.IdSalida IS NULL
                   ORDER BY I.IdIngreso DESC LIMIT 1""",
                (id_bicicleta,),
            )
            return cur.fetchone()

    @staticmethod
    def ingresos_activos_de_usuario(id_usuario: int) -> list:
        """RN-03: usados para validar y mostrar el/los ingresos activos antes de la salida."""
        with get_cursor() as cur:
            cur.execute(
                """SELECT I.*, B.Marca, B.Modelo, B.Color, B.NumeroSerie, E.CodigoEspacio
                   FROM Ingresos I
                   LEFT JOIN Salidas S ON S.IdIngreso = I.IdIngreso
                   INNER JOIN Bicicletas B ON B.IdBicicleta = I.IdBicicleta
                   INNER JOIN Espacios E ON E.IdEspacio = I.IdEspacio
                   WHERE I.IdUsuario = %s AND S.IdSalida IS NULL""",
                (id_usuario,),
            )
            return cur.fetchall()

    @staticmethod
    def crear_ingreso(id_bicicleta: int, id_usuario: int, id_espacio: int) -> int:
        with get_cursor(commit=True) as cur:
            cur.execute(
                """INSERT INTO Ingresos (IdBicicleta, IdUsuario, IdEspacio)
                   VALUES (%s, %s, %s)""",
                (id_bicicleta, id_usuario, id_espacio),
            )
            return cur.lastrowid

    @staticmethod
    def crear_salida(id_ingreso: int) -> int:
        with get_cursor(commit=True) as cur:
            cur.execute("INSERT INTO Salidas (IdIngreso) VALUES (%s)", (id_ingreso,))
            return cur.lastrowid

    @staticmethod
    def movimientos_por_rango(fecha_inicio: datetime, fecha_fin: datetime) -> list:
        with get_cursor() as cur:
            cur.execute(
                """SELECT I.IdIngreso, U.Documento, U.Nombres, U.Apellidos,
                          B.NumeroSerie, E.CodigoEspacio, I.FechaIngreso, S.FechaSalida
                   FROM Ingresos I
                   INNER JOIN Usuarios U ON U.IdUsuario = I.IdUsuario
                   INNER JOIN Bicicletas B ON B.IdBicicleta = I.IdBicicleta
                   INNER JOIN Espacios E ON E.IdEspacio = I.IdEspacio
                   LEFT JOIN Salidas S ON S.IdIngreso = I.IdIngreso
                   WHERE I.FechaIngreso BETWEEN %s AND %s
                   ORDER BY I.FechaIngreso DESC""",
                (fecha_inicio, fecha_fin),
            )
            return cur.fetchall()


class ReservaDAO:
    @staticmethod
    def reserva_activa_de_usuario(id_usuario: int) -> Optional[dict]:
        with get_cursor() as cur:
            cur.execute(
                """SELECT R.*, E.CodigoEspacio FROM Reservas R
                   INNER JOIN Espacios E ON E.IdEspacio = R.IdEspacio
                   WHERE R.IdUsuario = %s AND R.Estado = 'Activa'
                   ORDER BY R.IdReserva DESC LIMIT 1""",
                (id_usuario,),
            )
            return cur.fetchone()

    @staticmethod
    def crear(id_usuario: int, id_bicicleta: int, id_espacio: int) -> dict:
        ahora = datetime.now()
        expiracion = ahora + timedelta(minutes=RESERVA_MINUTOS_VALIDEZ)
        with get_cursor(commit=True) as cur:
            cur.execute(
                """INSERT INTO Reservas (IdUsuario, IdBicicleta, IdEspacio, FechaExpiracion, Estado)
                   VALUES (%s, %s, %s, %s, 'Activa')""",
                (id_usuario, id_bicicleta, id_espacio, expiracion),
            )
            id_reserva = cur.lastrowid
        return {
            "id_reserva": id_reserva,
            "fecha_reserva": ahora,
            "fecha_expiracion": expiracion,
        }

    @staticmethod
    def listar_activas_expiradas() -> list:
        """RN-05: reservas cuya vigencia de 30 minutos ya se cumplió."""
        with get_cursor() as cur:
            cur.execute(
                "SELECT * FROM Reservas WHERE Estado = 'Activa' AND FechaExpiracion < %s",
                (datetime.now(),),
            )
            return cur.fetchall()

    @staticmethod
    def marcar_estado(id_reserva: int, estado: str):
        with get_cursor(commit=True) as cur:
            cur.execute("UPDATE Reservas SET Estado = %s WHERE IdReserva = %s", (estado, id_reserva))


class IncidenteDAO:
    @staticmethod
    def crear(id_usuario, id_bicicleta, tipo, descripcion) -> int:
        with get_cursor(commit=True) as cur:
            cur.execute(
                """INSERT INTO Incidentes (IdUsuario, IdBicicleta, TipoIncidente, Descripcion)
                   VALUES (%s, %s, %s, %s)""",
                (id_usuario, id_bicicleta, tipo, descripcion),
            )
            return cur.lastrowid

    @staticmethod
    def por_rango(fecha_inicio: datetime, fecha_fin: datetime) -> list:
        with get_cursor() as cur:
            cur.execute(
                """SELECT Inc.IdIncidente, Inc.TipoIncidente, Inc.Descripcion, Inc.FechaIncidente,
                          U.Documento, U.Nombres, B.NumeroSerie
                   FROM Incidentes Inc
                   LEFT JOIN Usuarios U ON U.IdUsuario = Inc.IdUsuario
                   LEFT JOIN Bicicletas B ON B.IdBicicleta = Inc.IdBicicleta
                   WHERE Inc.FechaIncidente BETWEEN %s AND %s
                   ORDER BY Inc.FechaIncidente DESC""",
                (fecha_inicio, fecha_fin),
            )
            return cur.fetchall()
'@
Set-Content -Path "backend\dao.py" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\dao.py" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
"""
Patrones de diseño aplicados (sección 13 del ERS):

- FACTORY: creación de usuarios validando el rol (Administrador, Vigilante,
  Usuario/Ciclista) sin acoplar esa lógica al endpoint.
- STRATEGY: generación de reportes en distintos formatos (JSON, CSV, PDF)
  bajo una misma interfaz, permitiendo agregar nuevos formatos sin tocar
  el código existente.
- OBSERVER: notificación desacoplada de eventos del sistema (disponibilidad
  de cupos, expiración de reservas) a cualquier "suscriptor" interesado.
"""

import csv
import io
from abc import ABC, abstractmethod
from typing import List

from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse

from security import hash_password

ROLES_VALIDOS = {"Administrador", "Vigilante", "Usuario"}


# ---------------------------------------------------------------------------
# FACTORY
# ---------------------------------------------------------------------------
class UsuarioFactory:
    """Crea el payload de un nuevo usuario validando reglas según su rol."""

    @staticmethod
    def crear_payload(documento, nombres, apellidos, correo, telefono, contrasena, rol) -> dict:
        rol_normalizado = rol if rol in ROLES_VALIDOS else "Usuario"

        if rol_normalizado == "Administrador":
            # Regla de ejemplo: en este proyecto el rol Administrador no se
            # autoasigna desde el registro público; se degrada a Usuario y
            # debe ser promovido manualmente por otro Administrador (RN-08).
            rol_normalizado = "Usuario"

        return {
            "documento": documento,
            "nombres": nombres,
            "apellidos": apellidos,
            "correo": correo,
            "telefono": telefono,
            "password_hash": hash_password(contrasena),
            "rol": rol_normalizado,
        }


# ---------------------------------------------------------------------------
# STRATEGY (RF-10: exportar reportes en distintos formatos)
# ---------------------------------------------------------------------------
class ReporteExportador(ABC):
    """Interfaz común para las estrategias de exportación de reportes."""

    @abstractmethod
    def exportar(self, datos: List[dict], nombre_reporte: str):
        raise NotImplementedError


class JSONExportStrategy(ReporteExportador):
    def exportar(self, datos: List[dict], nombre_reporte: str):
        return {"status": "success", "tipo": "json", "total_registros": len(datos), "datos": datos}


class CSVExportStrategy(ReporteExportador):
    def exportar(self, datos: List[dict], nombre_reporte: str):
        buffer = io.StringIO()
        if datos:
            escritor = csv.DictWriter(buffer, fieldnames=list(datos[0].keys()))
            escritor.writeheader()
            for fila in datos:
                escritor.writerow(fila)
        else:
            buffer.write("Sin registros para el período seleccionado\n")

        buffer.seek(0)
        return StreamingResponse(
            iter([buffer.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{nombre_reporte}.csv"'},
        )


class PDFExportStrategy(ReporteExportador):
    def exportar(self, datos: List[dict], nombre_reporte: str):
        try:
            from fpdf import FPDF
        except ImportError:
            raise HTTPException(
                status_code=501,
                detail="La exportación a PDF requiere el paquete 'fpdf2' en el backend.",
            )

        pdf = FPDF(orientation="L", unit="mm", format="A4")
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, f"Reporte: {nombre_reporte}", ln=True)
        pdf.set_font("Helvetica", "", 9)

        if not datos:
            pdf.cell(0, 10, "Sin registros para el período seleccionado.", ln=True)
        else:
            columnas = list(datos[0].keys())
            ancho_col = 277 / max(len(columnas), 1)
            pdf.set_font("Helvetica", "B", 8)
            for col in columnas:
                pdf.cell(ancho_col, 8, str(col)[:20], border=1)
            pdf.ln()
            pdf.set_font("Helvetica", "", 8)
            for fila in datos:
                for col in columnas:
                    pdf.cell(ancho_col, 8, str(fila.get(col, ""))[:24], border=1)
                pdf.ln()

        salida = bytes(pdf.output(dest="S"))
        return Response(
            content=salida,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{nombre_reporte}.pdf"'},
        )


def obtener_estrategia(formato: str) -> ReporteExportador:
    estrategias = {
        "json": JSONExportStrategy(),
        "csv": CSVExportStrategy(),
        "pdf": PDFExportStrategy(),
    }
    estrategia = estrategias.get(formato.lower())
    if estrategia is None:
        raise HTTPException(status_code=400, detail="Formato de reporte no soportado. Use json, csv o pdf.")
    return estrategia


# ---------------------------------------------------------------------------
# OBSERVER (notificaciones de disponibilidad / expiración de reservas)
# ---------------------------------------------------------------------------
class Observer(ABC):
    @abstractmethod
    def actualizar(self, evento: str, datos: dict):
        raise NotImplementedError


class LogObserver(Observer):
    """Observer de referencia: registra el evento en consola/servidor."""

    def actualizar(self, evento: str, datos: dict):
        print(f"[Notificación] evento={evento} datos={datos}")


class NotificadorDisponibilidad:
    """Sujeto (Subject) observable: dispara eventos a todos sus observadores."""

    def __init__(self):
        self._observers: List[Observer] = []

    def suscribir(self, observer: Observer):
        self._observers.append(observer)

    def notificar(self, evento: str, datos: dict):
        for observer in self._observers:
            observer.actualizar(evento, datos)


# Instancia única utilizada por main.py para publicar eventos del dominio.
notificador = NotificadorDisponibilidad()
notificador.suscribir(LogObserver())
'@
Set-Content -Path "backend\patterns.py" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\patterns.py" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
fastapi==0.110.0
uvicorn==0.28.0
pydantic[email]==2.6.4
mysql-connector-python==8.1.0
passlib[bcrypt]==1.7.4
bcrypt==4.1.2
PyJWT==2.8.0
python-multipart==0.0.9
fpdf2==2.7.9
'@
Set-Content -Path "backend\requirements.txt" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\requirements.txt" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "backend" | Out-Null
$contenido = @'
FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
'@
Set-Content -Path "backend\Dockerfile" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> backend\Dockerfile" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "mysql-init" | Out-Null
$contenido = @'
SET NAMES utf8mb4;
SET foreign_key_checks = 0;

DROP DATABASE IF EXISTS ParqueaderoBicicletas;
CREATE DATABASE ParqueaderoBicicletas
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE ParqueaderoBicicletas;

SET foreign_key_checks = 0;

CREATE TABLE IF NOT EXISTS Roles (
    IdRol INT AUTO_INCREMENT PRIMARY KEY,
    NombreRol VARCHAR(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Usuarios (
    IdUsuario INT AUTO_INCREMENT PRIMARY KEY,
    Documento VARCHAR(20) NOT NULL UNIQUE,
    Nombres VARCHAR(100) NOT NULL,
    Apellidos VARCHAR(100) NOT NULL,
    Correo VARCHAR(100) UNIQUE,
    Telefono VARCHAR(20),
    PasswordHash VARCHAR(255) NOT NULL,
    Estado VARCHAR(20) DEFAULT 'Activo',
    FechaRegistro DATETIME DEFAULT CURRENT_TIMESTAMP,
    IdRol INT NOT NULL,
    FOREIGN KEY (IdRol) REFERENCES Roles(IdRol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Bicicletas (
    IdBicicleta INT AUTO_INCREMENT PRIMARY KEY,
    IdUsuario INT NOT NULL,
    Marca VARCHAR(50),
    Modelo VARCHAR(50),
    Color VARCHAR(30),
    NumeroSerie VARCHAR(100) UNIQUE NOT NULL,
    Foto VARCHAR(255),
    Estado VARCHAR(20) DEFAULT 'Activa',
    FOREIGN KEY (IdUsuario) REFERENCES Usuarios(IdUsuario)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Espacios (
    IdEspacio INT AUTO_INCREMENT PRIMARY KEY,
    CodigoEspacio VARCHAR(20) UNIQUE,
    Estado VARCHAR(20) DEFAULT 'Disponible'  -- Disponible | Ocupado | Reservado
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Reservas (
    IdReserva INT AUTO_INCREMENT PRIMARY KEY,
    IdUsuario INT NOT NULL,
    IdBicicleta INT NOT NULL,
    IdEspacio INT NOT NULL,
    FechaReserva DATETIME DEFAULT CURRENT_TIMESTAMP,
    FechaExpiracion DATETIME,
    Estado VARCHAR(20) DEFAULT 'Activa',  -- Activa | Convertida | Expirada | Cancelada
    FOREIGN KEY (IdUsuario) REFERENCES Usuarios(IdUsuario),
    FOREIGN KEY (IdBicicleta) REFERENCES Bicicletas(IdBicicleta),
    FOREIGN KEY (IdEspacio) REFERENCES Espacios(IdEspacio)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Ingresos (
    IdIngreso INT AUTO_INCREMENT PRIMARY KEY,
    IdBicicleta INT NOT NULL,
    IdUsuario INT NOT NULL,
    IdEspacio INT NOT NULL,
    FechaIngreso DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (IdBicicleta) REFERENCES Bicicletas(IdBicicleta),
    FOREIGN KEY (IdUsuario) REFERENCES Usuarios(IdUsuario),
    FOREIGN KEY (IdEspacio) REFERENCES Espacios(IdEspacio)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Salidas (
    IdSalida INT AUTO_INCREMENT PRIMARY KEY,
    IdIngreso INT NOT NULL,
    FechaSalida DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (IdIngreso) REFERENCES Ingresos(IdIngreso)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS Incidentes (
    IdIncidente INT AUTO_INCREMENT PRIMARY KEY,
    IdUsuario INT,
    IdBicicleta INT,
    TipoIncidente VARCHAR(100),
    Descripcion TEXT,
    FechaIncidente DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (IdUsuario) REFERENCES Usuarios(IdUsuario),
    FOREIGN KEY (IdBicicleta) REFERENCES Bicicletas(IdBicicleta)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET foreign_key_checks = 1;

-- Roles alineados al ERS (sección 12.1): Administrador, Vigilante, Usuario (Ciclista)
INSERT IGNORE INTO Roles (NombreRol) VALUES
('Administrador'),
('Vigilante'),
('Usuario');

-- Cupos de ejemplo del parqueadero
INSERT IGNORE INTO Espacios (CodigoEspacio) VALUES
('A01'), ('A02'), ('A03'), ('A04'), ('A05');

-- NOTA IMPORTANTE SOBRE USUARIOS SEMILLA:
-- Ya no se inserta un usuario con contraseña "adivinada" en SQL, porque el
-- backend ahora usa bcrypt (con salt aleatorio distinto en cada hash) y no
-- es correcto generar ese hash a mano dentro de un script SQL plano.
-- Para crear el primer Administrador sigue el procedimiento del README
-- ("Crear el primer Administrador"):
--   1) Regístrate normalmente desde el formulario /register (quedas como 'Usuario').
--   2) Promuévete a Administrador con un UPDATE puntual en MySQL.
'@
Set-Content -Path "mysql-init\init.sql" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> mysql-init\init.sql" -ForegroundColor Green

$contenido = @'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>voy. - Gestión de Parqueaderos de Bicicletas</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <nav class="barra-navegacion">
        <div class="marca-logo">🚴 voy<span>.</span></div>
        <div class="enlaces-nav">
            <a href="javascript:void(0)" onclick="mostrarInicio(event)">Inicio</a>
            <a href="javascript:void(0)" onclick="mostrarUbicaciones(event)">Ubicaciones</a>
            <a href="javascript:void(0)" onclick="mostrarPlanes(event)">Planes</a>
            <a href="javascript:void(0)" onclick="mostrarRegistro(event)">Registro</a>
            <button onclick="cerrarSesion()" id="btn-nav-logout" class="ocultar-seccion">Salir</button>
        </div>
    </nav>

    <main class="contenedor-landing">

        <!-- SECCIÓN 1: LOGIN -->
        <div id="seccion-login" class="modulo-login-premium">
            <div class="columna-texto-login">
                <h1>Tu bici te mueve.<br>Nosotros <span class="texto-resaltado">la cuidamos.</span></h1>
                <p>Parqueo de bicicletas seguro y cómodo, para una Medellín más limpia y sostenible.</p>
            </div>
            <div class="columna-formulario-login">
                <div class="tarjeta-autenticacion">
                    <h2>🔐 Control de Acceso</h2>
                    <label>Usuario / Correo</label>
                    <input type="text" id="login-usuario" placeholder="correo@dominio.com">

                    <label>Contraseña</label>
                    <input type="password" id="login-password" placeholder="••••••••">

                    <button onclick="autenticarUsuario()" class="btn-principal">Acceder al Panel</button>
                    <p class="texto-pequeno" style="margin-top:1rem; color:#334155;">
                        ¿No tienes cuenta?
                        <a href="javascript:void(0)" onclick="mostrarRegistro(event)" style="color:var(--magenta); font-weight:700;">Regístrate aquí</a>
                    </p>
                </div>
            </div>
        </div>

        <!-- SECCIÓN: REGISTRO -->
        <div id="seccion-registro" class="tarjeta-autenticacion ocultar-seccion" style="margin: 2rem auto; max-width: 640px;">
            <h2>📝 Registro de Usuario</h2>

            <label>Documento</label>
            <input type="text" id="registro-documento" placeholder="Ej: 12345678">

            <label>Nombres</label>
            <input type="text" id="registro-nombres" placeholder="Ej: Isabel Cristina">

            <label>Apellidos</label>
            <input type="text" id="registro-apellidos" placeholder="Ej: Acevedo Guirales">

            <label>Correo</label>
            <input type="email" id="registro-correo" placeholder="Ej: correo@dominio.com">

            <label>Teléfono</label>
            <input type="text" id="registro-telefono" placeholder="Ej: 3226753558">

            <label>Contraseña</label>
            <input type="password" id="registro-password" placeholder="••••••••">

            <label>Tipo de cuenta</label>
            <select id="registro-rol">
                <option value="Usuario">Usuario (Ciclista)</option>
                <option value="Vigilante">Vigilante</option>
            </select>
            <p class="texto-pequeno" style="color:#64748b; margin-top:-1rem;">
                Las cuentas de Administrador se asignan manualmente por otro Administrador.
            </p>

            <button onclick="registrarUsuario()" class="btn-principal">Crear cuenta</button>
            <button onclick="mostrarLogin(event)" class="btn-secundario" style="margin-top:0.75rem;">Volver al inicio</button>
        </div>

        <!-- SECCIÓN: UBICACIONES -->
        <div id="seccion-ubicaciones" class="tarjeta-autenticacion ocultar-seccion" style="margin-top:1.5rem;">
            <h2>📍 Ubicaciones</h2>
            <p>Selecciona el punto más cercano para tu parqueadero de bicicleta.</p>
            <ul>
                <li>Parqueadero 1 - Centro Comercial</li>
                <li>Parqueadero 2 - Estación de Metro</li>
                <li>Parqueadero 3 - Universidad</li>
            </ul>
            <button onclick="mostrarInicio()" class="btn-secundario" style="margin-top:0.75rem;">Volver al inicio</button>
        </div>

        <!-- SECCIÓN: PLANES -->
        <div id="seccion-planes" class="tarjeta-autenticacion ocultar-seccion" style="margin-top:1.5rem;">
            <h2>💳 Planes</h2>
            <p>Revisa las opciones disponibles para el uso de parqueaderos.</p>
            <ul>
                <li>Plan Diario - Acceso por 24 horas</li>
                <li>Plan Mensual - Uso ilimitado durante un mes</li>
                <li>Plan Corporativo - Para empresas y grupos</li>
            </ul>
            <button onclick="mostrarInicio()" class="btn-secundario" style="margin-top:0.75rem;">Volver al inicio</button>
        </div>

        <!-- SECCIÓN: PANEL OPERATIVO MULTI-ROL -->
        <div id="panel-sistema" class="ocultar-seccion">
            <div class="hero-sistema">
                <span id="franja-rol" class="franja-rol">Rol</span>
                <h1 id="saludo-rol">Panel de Control</h1>
                <p>Monitoreo operativo del parqueadero en tiempo real.</p>
            </div>

            <!-- RF-06: Disponibilidad -->
            <div class="tarjeta-contador-premium">
                <div class="bloque-contador">
                    <p>Cupos Libres</p>
                    <div id="contador-libres" class="numero-cupos-premium">--</div>
                </div>
                <div class="bloque-contador">
                    <p>Cupos Ocupados</p>
                    <div id="contador-ocupados" class="numero-cupos-premium ocupados">--</div>
                </div>
                <div class="bloque-contador">
                    <p>Cupos Reservados</p>
                    <div id="contador-reservados" class="numero-cupos-premium reservados">--</div>
                </div>
            </div>

            <div class="grilla-operaciones-premium">

                <!-- RF-04 / RF-05: Vigilante y Administrador -->
                <div id="bloque-gestion-operario" class="tarjeta-accion-premium ocultar-seccion">
                    <h3>🛠️ Registro de Movimientos</h3>
                    <p>Gestión de ingresos y salidas de bicicletas.</p>

                    <label>Documento del Ciclista</label>
                    <input type="text" id="doc-movimiento" placeholder="Ej: 1017200XXX">

                    <label>ID de Bicicleta (solo si el usuario tiene más de una)</label>
                    <input type="text" id="bici-movimiento" placeholder="Opcional">

                    <div style="display: flex; gap: 1rem; margin-top: 1rem;">
                        <button onclick="procesarMovimiento('ingreso')" class="btn-principal btn-turquesa">Registrar Entrada</button>
                        <button onclick="procesarMovimiento('salida')" class="btn-principal btn-naranja">Registrar Salida</button>
                    </div>
                </div>

                <!-- RF-07: Solo rol Usuario -->
                <div id="bloque-reservas-usuario" class="tarjeta-accion-premium acento-amarillo ocultar-seccion">
                    <h3>⏱️ Reservar Cupo Anticipado</h3>
                    <p>Bloquea un espacio disponible durante 30 minutos mientras llegas al parqueadero.</p>
                    <button onclick="crearReserva()" class="btn-principal btn-amarillo">Reservar mi cupo</button>
                </div>

                <!-- RF-08: Vigilante y Administrador -->
                <div class="tarjeta-accion-premium acento-magenta">
                    <h3>⚠️ Reporte de Novedades e Incidentes</h3>
                    <p>Registro de daños, sospechas u objetos olvidados.</p>

                    <label>Tipo de incidente</label>
                    <select id="incidente-tipo">
                        <option value="daño">Daño</option>
                        <option value="sospecha">Sospecha</option>
                        <option value="perdida">Pérdida</option>
                        <option value="otro">Otro</option>
                    </select>

                    <label>Documento del usuario asociado (opcional)</label>
                    <input type="text" id="incidente-doc" placeholder="Opcional">

                    <label>ID de Bicicleta asociada (opcional)</label>
                    <input type="text" id="incidente-bici" placeholder="Opcional">

                    <label>Descripción de la Novedad</label>
                    <input type="text" id="incidente-descripcion" placeholder="Ej: Cadena suelta o rayón lateral">

                    <button onclick="registrarIncidente()" class="btn-principal btn-magenta">Reportar Incidente</button>
                </div>

                <!-- RF-10: Solo Administrador -->
                <div id="bloque-reportes-admin" class="tarjeta-accion-premium acento-naranja ocultar-seccion" style="grid-column: 1 / -1;">
                    <h3>📊 Reportes de Ocupación e Incidentes</h3>
                    <p>Filtra el historial por rango de fechas y expórtalo a CSV o PDF.</p>

                    <div style="display:flex; gap:1rem; flex-wrap:wrap;">
                        <div style="flex:1; min-width:180px;">
                            <label>Desde</label>
                            <input type="datetime-local" id="reporte-fecha-inicio">
                        </div>
                        <div style="flex:1; min-width:180px;">
                            <label>Hasta</label>
                            <input type="datetime-local" id="reporte-fecha-fin">
                        </div>
                        <div style="flex:1; min-width:180px;">
                            <label>Tipo</label>
                            <select id="reporte-tipo">
                                <option value="movimientos">Movimientos (ingresos/salidas)</option>
                                <option value="incidentes">Incidentes</option>
                            </select>
                        </div>
                    </div>

                    <div style="display:flex; gap:1rem; margin-top:0.5rem; flex-wrap:wrap;">
                        <button onclick="generarReporte()" class="btn-principal btn-naranja" style="width:auto; padding:0.8rem 1.5rem;">Generar reporte</button>
                        <button onclick="exportarReporte('csv')" class="btn-secundario" style="width:auto; padding:0.8rem 1.5rem;">Exportar CSV</button>
                        <button onclick="exportarReporte('pdf')" class="btn-secundario" style="width:auto; padding:0.8rem 1.5rem;">Exportar PDF</button>
                    </div>

                    <div id="reporte-contenedor-tabla" style="margin-top:1.5rem; overflow-x:auto;"></div>
                </div>
            </div>
        </div>

    </main>

    <script src="js/script.js"></script>
</body>
</html>
'@
Set-Content -Path "index.html" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> index.html" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "css" | Out-Null
$contenido = @'
:root {
    /* Paleta "Medellín" */
    --verde-montana: #1B6B3C;
    --verde-montana-oscuro: #0F4A2A;
    --magenta: #D6007F;
    --naranja: #FF6B00;
    --turquesa: #00A8A0;
    --amarillo: #FFC800;

    --texto-oscuro: #14261C;
    --texto-claro: #ffffff;
    --gris-suave: rgba(255, 255, 255, 0.94);
    --borde-curvo: 24px;

    --degradado-medellin: linear-gradient(120deg, var(--verde-montana) 0%, var(--turquesa) 45%, var(--magenta) 100%);
}

* { box-sizing: border-box; }

body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    margin: 0;
    padding: 0;
    min-height: 100vh;
    color: var(--texto-oscuro);
    background: var(--degradado-medellin);
    background-attachment: fixed;
}

/* BARRA DE NAVEGACIÓN */
.barra-navegacion {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.25rem 4rem;
    background-color: rgba(255, 255, 255, 0.96);
    backdrop-filter: blur(10px);
    border-bottom: 4px solid var(--naranja);
    position: sticky;
    top: 0;
    z-index: 10;
}

.marca-logo {
    font-size: 2rem;
    font-weight: 800;
    color: var(--verde-montana-oscuro);
    letter-spacing: -1px;
}

.marca-logo span { color: var(--magenta); }

.enlaces-nav a {
    text-decoration: none;
    color: var(--verde-montana-oscuro);
    font-weight: 700;
    margin-right: 2rem;
    font-size: 1rem;
    transition: color 0.15s ease;
}

.enlaces-nav a:hover { color: var(--turquesa); }

.enlaces-nav button {
    background-color: var(--magenta);
    color: white;
    border: none;
    padding: 0.6rem 1.4rem;
    border-radius: 30px;
    font-weight: 700;
    cursor: pointer;
}

/* MAQUETACIÓN */
.contenedor-landing {
    max-width: 1200px;
    margin: 4rem auto;
    padding: 0 2rem;
}

.modulo-login-premium {
    display: grid;
    grid-template-columns: 1.2fr 0.8fr;
    gap: 4rem;
    align-items: center;
    width: 100%;
}

.columna-texto-login h1 {
    font-size: 3.6rem;
    line-height: 1.12;
    font-weight: 800;
    color: var(--texto-claro);
    margin: 0 0 1.7rem 0;
    max-width: 600px;
    text-shadow: 2px 2px 10px rgba(0, 0, 0, 0.35);
}

.texto-resaltado { color: var(--amarillo) !important; }

.columna-texto-login p {
    font-size: 1.4rem;
    color: #ffffff;
    line-height: 1.6;
    margin: 0 0 2rem 0;
    max-width: 500px;
    font-weight: 600;
    text-shadow: 1px 1px 6px rgba(0, 0, 0, 0.35);
}

/* TARJETAS */
.tarjeta-autenticacion {
    background: var(--gris-suave);
    backdrop-filter: blur(8px);
    padding: 3rem;
    border-radius: var(--borde-curvo);
    box-shadow: 0 20px 40px rgba(15, 74, 42, 0.25);
    border: 1px solid rgba(0, 168, 160, 0.25);
}

.tarjeta-autenticacion h2 {
    margin-top: 0;
    font-size: 1.6rem;
    color: var(--verde-montana-oscuro);
    margin-bottom: 2rem;
    font-weight: 800;
}

.tarjeta-autenticacion ul { padding-left: 1.2rem; }
.tarjeta-autenticacion li { margin-bottom: 0.5rem; }

label {
    display: block;
    font-weight: 700;
    margin-bottom: 0.5rem;
    font-size: 0.9rem;
    color: var(--verde-montana-oscuro);
}

input, select {
    width: 100%;
    padding: 1rem;
    margin-bottom: 1.5rem;
    border: 2px solid #cbd5e1;
    border-radius: 12px;
    box-sizing: border-box;
    font-size: 1rem;
    color: var(--texto-oscuro);
    background-color: #f8fafc;
    font-family: inherit;
}

input:focus, select:focus {
    outline: none;
    border-color: var(--turquesa);
}

/* BOTONES */
.btn-principal {
    width: 100%;
    background-color: var(--verde-montana);
    color: white;
    padding: 1.1rem;
    border: none;
    border-radius: 30px;
    font-size: 1.05rem;
    font-weight: 700;
    cursor: pointer;
    box-shadow: 0 4px 12px rgba(27, 107, 60, 0.3);
    transition: transform 0.1s ease, background-color 0.15s ease;
}

.btn-principal:hover { background-color: var(--verde-montana-oscuro); transform: translateY(-1px); }

.btn-secundario {
    width: 100%;
    background-color: transparent;
    color: var(--verde-montana-oscuro);
    padding: 0.9rem;
    border: 2px solid var(--verde-montana);
    border-radius: 30px;
    font-size: 1rem;
    font-weight: 700;
    cursor: pointer;
}

.btn-turquesa { background-color: var(--turquesa); box-shadow: 0 4px 12px rgba(0, 168, 160, 0.3); }
.btn-naranja { background-color: var(--naranja); box-shadow: 0 4px 12px rgba(255, 107, 0, 0.3); }
.btn-magenta { background-color: var(--magenta); box-shadow: 0 4px 12px rgba(214, 0, 127, 0.3); }
.btn-amarillo { background-color: var(--amarillo); color: var(--texto-oscuro); box-shadow: 0 4px 12px rgba(255, 200, 0, 0.35); }

.btn-rojo-premium { background-color: var(--naranja); }

/* PANEL INTERNO */
.hero-sistema h1 { font-size: 2.6rem; font-weight: 800; color: var(--texto-claro); text-shadow: 1px 1px 8px rgba(0,0,0,0.3); }
.hero-sistema p { color: #ffffff; font-weight: 600; }

.tarjeta-contador-premium {
    background-color: var(--verde-montana-oscuro);
    color: white;
    text-align: center;
    padding: 2rem;
    border-radius: var(--borde-curvo);
    max-width: 700px;
    margin: 0 auto 3rem auto;
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1rem;
}

.bloque-contador { padding: 0.5rem; }
.bloque-contador p { margin: 0 0 0.3rem 0; opacity: 0.85; font-size: 0.9rem; }
.numero-cupos-premium { font-size: 3.2rem; font-weight: 800; color: var(--amarillo); }
.numero-cupos-premium.ocupados { color: var(--naranja); }
.numero-cupos-premium.reservados { color: var(--turquesa); }

.grilla-operaciones-premium { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }

.tarjeta-accion-premium {
    background: var(--gris-suave);
    backdrop-filter: blur(8px);
    padding: 2.5rem;
    border-radius: var(--borde-curvo);
    border: 1px solid #e2e8f0;
    border-top: 5px solid var(--turquesa);
}

.tarjeta-accion-premium h3 { color: var(--verde-montana-oscuro); font-weight: 800; margin-top: 0; }

.tarjeta-accion-premium.acento-naranja { border-top-color: var(--naranja); }
.tarjeta-accion-premium.acento-magenta { border-top-color: var(--magenta); }
.tarjeta-accion-premium.acento-amarillo { border-top-color: var(--amarillo); }

.franja-rol {
    display: inline-block;
    padding: 0.3rem 0.9rem;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 700;
    color: white;
    background-color: var(--magenta);
    margin-bottom: 1rem;
}

.texto-pequeno { font-size: 0.9rem; }

table.tabla-reporte { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }
table.tabla-reporte th { background-color: var(--verde-montana); color: white; padding: 0.6rem; text-align: left; }
table.tabla-reporte td { padding: 0.5rem 0.6rem; border-bottom: 1px solid #e2e8f0; }
table.tabla-reporte tr:nth-child(even) { background-color: #f8fafc; }

.ocultar-seccion { display: none !important; }

@media (max-width: 900px) {
    .barra-navegacion { padding: 1rem 1.5rem; flex-direction: column; gap: 0.75rem; }
    .modulo-login-premium { grid-template-columns: 1fr; }
    .grilla-operaciones-premium { grid-template-columns: 1fr; }
    .tarjeta-contador-premium { grid-template-columns: 1fr; }
}
'@
Set-Content -Path "css\style.css" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> css\style.css" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path "js" | Out-Null
$contenido = @'
const API_URL = "http://localhost:8000";

let sesion = {
    token: null,
    rol: null,
    nombres: null,
    documento: null,
};

document.addEventListener("DOMContentLoaded", () => {
    cerrarSesion();
});

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------
function limpiarCampos(ids) {
    ids.forEach(id => {
        const elemento = document.getElementById(id);
        if (elemento) elemento.value = "";
    });
}

function limpiarFormularioLogin() { limpiarCampos(["login-usuario", "login-password"]); }
function limpiarFormularioRegistro() {
    limpiarCampos(["registro-documento", "registro-nombres", "registro-apellidos",
        "registro-correo", "registro-telefono", "registro-password"]);
}
function limpiarFormularioMovimientos() { limpiarCampos(["doc-movimiento", "bici-movimiento"]); }
function limpiarFormularioIncidente() {
    limpiarCampos(["incidente-doc", "incidente-bici", "incidente-descripcion"]);
}

function encabezadosAuth() {
    return sesion.token
        ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${sesion.token}` }
        : { 'Content-Type': 'application/json' };
}

async function manejarRespuesta(respuesta) {
    let resultado = null;
    try { resultado = await respuesta.json(); } catch (e) { /* respuesta no-JSON (csv/pdf) */ }

    if (respuesta.status === 401) {
        alert("⏳ Tu sesión expiró. Inicia sesión nuevamente.");
        cerrarSesion();
        return null;
    }
    return { ok: respuesta.ok, resultado, respuesta };
}

// ---------------------------------------------------------------------------
// Autenticación (RF-01, RF-02)
// ---------------------------------------------------------------------------
async function autenticarUsuario() {
    const usuario = document.getElementById("login-usuario").value.trim();
    const contrasena = document.getElementById("login-password").value.trim();

    if (!usuario || !contrasena) {
        alert("⚠️ Por favor, complete todos los campos de acceso.");
        return;
    }

    try {
        const respuesta = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usuario, contrasena })
        });

        const paquete = await manejarRespuesta(respuesta);
        if (!paquete) return;
        const { ok, resultado } = paquete;
        const mensaje = resultado?.mensaje || resultado?.detail || "Error de servidor desconocido.";

        if (ok && resultado?.status === "success") {
            sesion = {
                token: resultado.token,
                rol: resultado.rol,
                nombres: resultado.nombres,
                documento: resultado.documento,
            };
            limpiarFormularioLogin();
            mostrarPanelSistema();
        } else {
            alert("❌ " + mensaje);
        }
    } catch (error) {
        console.error('Error de red en login:', error);
        alert("🔌 Error del sistema: No hay conexión con el servidor. Verifique Docker Desktop.");
    }
}

function mostrarPanelSistema() {
    document.getElementById("seccion-login").classList.add("ocultar-seccion");
    document.getElementById("panel-sistema").classList.remove("ocultar-seccion");
    document.getElementById("btn-nav-logout").classList.remove("ocultar-seccion");

    const saludo = document.getElementById("saludo-rol");
    const franja = document.getElementById("franja-rol");
    const bloqueOperario = document.getElementById("bloque-gestion-operario");
    const bloqueUsuario = document.getElementById("bloque-reservas-usuario");
    const bloqueAdmin = document.getElementById("bloque-reportes-admin");

    franja.textContent = sesion.rol;
    saludo.innerHTML = `Hola, <span class="texto-resaltado">${sesion.nombres || sesion.documento}</span>`;

    bloqueOperario.classList.add("ocultar-seccion");
    bloqueUsuario.classList.add("ocultar-seccion");
    bloqueAdmin.classList.add("ocultar-seccion");

    if (sesion.rol === "Vigilante" || sesion.rol === "Administrador") {
        bloqueOperario.classList.remove("ocultar-seccion");
    }
    if (sesion.rol === "Usuario") {
        bloqueUsuario.classList.remove("ocultar-seccion");
    }
    if (sesion.rol === "Administrador") {
        bloqueAdmin.classList.remove("ocultar-seccion");
    }

    actualizarDisponibilidad();
}

function cerrarSesion() {
    sesion = { token: null, rol: null, nombres: null, documento: null };
    document.getElementById("panel-sistema").classList.add("ocultar-seccion");
    document.getElementById("seccion-ubicaciones").classList.add("ocultar-seccion");
    document.getElementById("seccion-planes").classList.add("ocultar-seccion");
    document.getElementById("seccion-registro").classList.add("ocultar-seccion");
    document.getElementById("btn-nav-logout").classList.add("ocultar-seccion");
    document.getElementById("seccion-login").classList.remove("ocultar-seccion");

    limpiarFormularioLogin();
}

function mostrarRegistro(event) {
    if (event) event.preventDefault();
    ["seccion-login", "seccion-ubicaciones", "seccion-planes", "panel-sistema"].forEach(id =>
        document.getElementById(id).classList.add("ocultar-seccion"));
    const registro = document.getElementById("seccion-registro");
    registro.classList.remove("ocultar-seccion");
    registro.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function mostrarLogin(event) {
    if (event) event.preventDefault();
    ["seccion-registro", "seccion-ubicaciones", "seccion-planes", "panel-sistema"].forEach(id =>
        document.getElementById(id).classList.add("ocultar-seccion"));
    const inicio = document.getElementById("seccion-login");
    inicio.classList.remove("ocultar-seccion");
    inicio.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function registrarUsuario() {
    const documento = document.getElementById("registro-documento").value.trim();
    const nombres = document.getElementById("registro-nombres").value.trim();
    const apellidos = document.getElementById("registro-apellidos").value.trim();
    const correo = document.getElementById("registro-correo").value.trim();
    const telefono = document.getElementById("registro-telefono").value.trim();
    const contrasena = document.getElementById("registro-password").value.trim();
    const rol = document.getElementById("registro-rol").value;

    if (!documento || !nombres || !apellidos || !correo || !contrasena) {
        alert("⚠️ Por favor, complete todos los campos de registro.");
        return;
    }

    try {
        const respuesta = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ documento, nombres, apellidos, correo, telefono, contrasena, rol })
        });

        const resultado = await respuesta.json();
        const mensaje = resultado?.mensaje || resultado?.detail || "Error desconocido al registrar usuario.";

        if (respuesta.ok && resultado?.status === "success") {
            alert("✅ " + mensaje);
            limpiarFormularioRegistro();
            mostrarLogin();
        } else {
            alert("❌ " + mensaje);
        }
    } catch (error) {
        alert("🔌 Error del sistema: No se pudo conectar con el backend.");
    }
}

// ---------------------------------------------------------------------------
// Disponibilidad (RF-06)
// ---------------------------------------------------------------------------
async function actualizarDisponibilidad() {
    try {
        const respuesta = await fetch(`${API_URL}/disponibilidad`);
        const datos = await respuesta.json();
        document.getElementById("contador-libres").textContent = datos.libres;
        document.getElementById("contador-ocupados").textContent = datos.ocupados;
        document.getElementById("contador-reservados").textContent = datos.reservados;
    } catch (error) {
        console.error("Error obteniendo disponibilidad:", error);
    }
}

// ---------------------------------------------------------------------------
// Ingresos / Salidas (RF-04, RF-05) - Vigilante / Administrador
// ---------------------------------------------------------------------------
async function procesarMovimiento(tipo) {
    const documento = document.getElementById("doc-movimiento").value.trim();
    const idBicicletaTexto = document.getElementById("bici-movimiento").value.trim();

    if (!documento) {
        alert("⚠️ Por favor, ingrese el documento del ciclista.");
        return;
    }

    const cuerpo = { documento };
    if (idBicicletaTexto) cuerpo.id_bicicleta = parseInt(idBicicletaTexto, 10);

    const ruta = tipo === 'ingreso' ? 'ingresos/registrar' : 'salidas/registrar';

    try {
        const respuesta = await fetch(`${API_URL}/${ruta}`, {
            method: 'POST',
            headers: encabezadosAuth(),
            body: JSON.stringify(cuerpo)
        });
        const paquete = await manejarRespuesta(respuesta);
        if (!paquete) return;
        const { ok, resultado } = paquete;
        const mensaje = resultado?.mensaje || resultado?.detail || "Error desconocido.";
        alert(ok ? "✅ " + mensaje : "❌ " + mensaje);
        if (ok) limpiarFormularioMovimientos();
        actualizarDisponibilidad();
    } catch (error) {
        alert("❌ Error de red al procesar el movimiento.");
    }
}

// ---------------------------------------------------------------------------
// Reservas (RF-07) - Usuario
// ---------------------------------------------------------------------------
async function crearReserva() {
    try {
        const respuesta = await fetch(`${API_URL}/reservas/crear`, {
            method: 'POST',
            headers: encabezadosAuth(),
            body: JSON.stringify({})
        });
        const paquete = await manejarRespuesta(respuesta);
        if (!paquete) return;
        const { ok, resultado } = paquete;
        const mensaje = resultado?.mensaje || resultado?.detail || "Error desconocido.";
        alert(ok ? "✅ " + mensaje : "❌ " + mensaje);
        actualizarDisponibilidad();
    } catch (error) {
        alert("❌ Error de red al crear la reserva.");
    }
}

// ---------------------------------------------------------------------------
// Incidentes (RF-08) - Vigilante / Administrador
// ---------------------------------------------------------------------------
async function registrarIncidente() {
    const documento_usuario = document.getElementById("incidente-doc").value.trim();
    const idBicicletaTexto = document.getElementById("incidente-bici").value.trim();
    const descripcion = document.getElementById("incidente-descripcion").value.trim();
    const tipo = document.getElementById("incidente-tipo").value;

    if (!descripcion) {
        alert("⚠️ Por favor, describa la novedad.");
        return;
    }

    const cuerpo = { tipo, descripcion };
    if (documento_usuario) cuerpo.documento_usuario = documento_usuario;
    if (idBicicletaTexto) cuerpo.id_bicicleta = parseInt(idBicicletaTexto, 10);

    try {
        const respuesta = await fetch(`${API_URL}/incidentes/registrar`, {
            method: 'POST',
            headers: encabezadosAuth(),
            body: JSON.stringify(cuerpo)
        });
        const paquete = await manejarRespuesta(respuesta);
        if (!paquete) return;
        const { ok, resultado } = paquete;
        const mensaje = resultado?.mensaje || resultado?.detail || "Error desconocido.";
        alert(ok ? "✅ " + mensaje : "❌ " + mensaje);
        if (ok) limpiarFormularioIncidente();
    } catch (error) {
        alert("❌ Error de red al guardar el incidente.");
    }
}

// ---------------------------------------------------------------------------
// Reportes (RF-10) - Administrador
// ---------------------------------------------------------------------------
async function generarReporte() {
    const fechaInicio = document.getElementById("reporte-fecha-inicio").value;
    const fechaFin = document.getElementById("reporte-fecha-fin").value;
    const tipo = document.getElementById("reporte-tipo").value;

    if (!fechaInicio || !fechaFin) {
        alert("⚠️ Selecciona el rango de fechas.");
        return;
    }

    const params = new URLSearchParams({
        fecha_inicio: fechaInicio, fecha_fin: fechaFin, tipo, formato: "json"
    });

    try {
        const respuesta = await fetch(`${API_URL}/reportes/generar?${params}`, {
            headers: encabezadosAuth()
        });
        const paquete = await manejarRespuesta(respuesta);
        if (!paquete) return;
        const { ok, resultado } = paquete;

        if (!ok) {
            alert("❌ " + (resultado?.detail || "No se pudo generar el reporte."));
            return;
        }

        pintarTablaReporte(resultado.datos || []);
        document.getElementById("reporte-contenedor-tabla").dataset.fechaInicio = fechaInicio;
        document.getElementById("reporte-contenedor-tabla").dataset.fechaFin = fechaFin;
        document.getElementById("reporte-contenedor-tabla").dataset.tipo = tipo;
    } catch (error) {
        alert("❌ Error de red al generar el reporte.");
    }
}

function pintarTablaReporte(datos) {
    const contenedor = document.getElementById("reporte-contenedor-tabla");
    if (!datos.length) {
        contenedor.innerHTML = "<p>No hay registros para el período seleccionado.</p>";
        return;
    }
    const columnas = Object.keys(datos[0]);
    let html = "<table class='tabla-reporte'><thead><tr>";
    columnas.forEach(c => html += `<th>${c}</th>`);
    html += "</tr></thead><tbody>";
    datos.forEach(fila => {
        html += "<tr>";
        columnas.forEach(c => html += `<td>${fila[c] ?? ''}</td>`);
        html += "</tr>";
    });
    html += "</tbody></table>";
    contenedor.innerHTML = html;
}

async function exportarReporte(formato) {
    const contenedor = document.getElementById("reporte-contenedor-tabla");
    const fechaInicio = contenedor.dataset.fechaInicio;
    const fechaFin = contenedor.dataset.fechaFin;
    const tipo = contenedor.dataset.tipo;

    if (!fechaInicio || !fechaFin) {
        alert("⚠️ Primero genera el reporte en pantalla.");
        return;
    }

    const params = new URLSearchParams({ fecha_inicio: fechaInicio, fecha_fin: fechaFin, tipo, formato });

    try {
        const respuesta = await fetch(`${API_URL}/reportes/generar?${params}`, {
            headers: encabezadosAuth()
        });
        if (!respuesta.ok) {
            const err = await respuesta.json().catch(() => ({}));
            alert("❌ " + (err.detail || "No se pudo exportar el reporte."));
            return;
        }
        const blob = await respuesta.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `reporte_${tipo}.${formato}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
    } catch (error) {
        alert("❌ Error de red al exportar el reporte.");
    }
}

// ---------------------------------------------------------------------------
// Navegación pública
// ---------------------------------------------------------------------------
function mostrarInicio() {
    ["seccion-registro", "seccion-ubicaciones", "seccion-planes", "panel-sistema"].forEach(id =>
        document.getElementById(id).classList.add("ocultar-seccion"));
    document.getElementById("seccion-login").classList.remove("ocultar-seccion");
}

function mostrarUbicaciones() {
    ["seccion-login", "seccion-registro", "seccion-planes", "panel-sistema"].forEach(id =>
        document.getElementById(id).classList.add("ocultar-seccion"));
    document.getElementById("seccion-ubicaciones").classList.remove("ocultar-seccion");
}

function mostrarPlanes() {
    ["seccion-login", "seccion-registro", "seccion-ubicaciones", "panel-sistema"].forEach(id =>
        document.getElementById(id).classList.add("ocultar-seccion"));
    document.getElementById("seccion-planes").classList.remove("ocultar-seccion");
}
'@
Set-Content -Path "js\script.js" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> js\script.js" -ForegroundColor Green

$contenido = @'
# Sistema Web para la Gestión de Parqueaderos de Bicicletas - Medellín 🚴✨

Proyecto para gestionar accesos, cupos y registros de parqueaderos de bicicletas.
Backend alineado con el Entregable Final del ERS (RF-01 a RF-10, RN-01 a RN-09,
arquitectura por capas y patrones de diseño MVC, DAO/Repository, Singleton,
Factory, Strategy y Observer).

## Requisitos previos
- Docker & Docker Compose instalados
- (Opcional) Cliente `mysql` o MySQL Workbench para conectarse a la base

## Servicios y puertos
- Frontend (nginx estático): http://localhost:8080/#
- Backend (FastAPI / Uvicorn): http://localhost:8000 — documentación interactiva en http://localhost:8000/docs
- MySQL (contenedor): puerto publicado 3307 -> 3306

## Inicio rápido (levantar todo)
```powershell
docker compose down -v
docker compose up -d --build
docker compose logs --follow backend
```

## Crear el primer Administrador
El backend ahora usa **bcrypt** (con salt aleatorio) para las contraseñas, por
lo que ya no se siembra un usuario Administrador con un hash "adivinado" en
`init.sql`. El procedimiento correcto es:

1. Abre `http://localhost:8080` y regístrate normalmente desde **Registro**
   (quedarás con rol `Usuario`).
2. Promociónate a `Administrador` con una consulta puntual en MySQL:
```powershell
docker exec -it voy_mysql mysql -uroot -proot -e "
USE ParqueaderoBicicletas;
UPDATE Usuarios U
JOIN Roles R ON R.NombreRol = 'Administrador'
SET U.IdRol = R.IdRol
WHERE U.Documento = 'TU_DOCUMENTO';"
```
3. Vuelve a iniciar sesión: ya tendrás el panel de Administrador (con el
   módulo de Reportes).

Los vigilantes se registran igual, seleccionando "Vigilante" en el formulario.

## Flujo funcional resumido
1. **Registro/Login** (RF-01, RF-02): JWT con expiración de 30 min.
2. **Registrar bicicleta** (RF-03): `POST /bicicletas/registrar` — necesario
   antes de poder registrar un ingreso o una reserva.
3. **Ingreso** (RF-04): el Vigilante ingresa el documento del ciclista;
   el sistema asigna automáticamente un espacio libre.
4. **Salida** (RF-05): el Vigilante ingresa el documento; el sistema busca
   el ingreso activo y libera el cupo.
5. **Disponibilidad** (RF-06): pública, sin login, `GET /disponibilidad`.
6. **Reserva** (RF-07): rol Usuario, `POST /reservas/crear`, expira sola a
   los 30 minutos (tarea en segundo plano) o se convierte en ingreso si el
   vigilante confirma la entrada antes.
7. **Incidentes** (RF-08): Vigilante/Administrador.
8. **Reportes** (RF-10): solo Administrador, `GET /reportes/generar` con
   `fecha_inicio`, `fecha_fin`, `tipo` (movimientos|incidentes) y
   `formato` (json|csv|pdf).

## Endpoints principales
| Método | Ruta                      | Rol requerido            |
|--------|---------------------------|---------------------------|
| POST   | /register                 | Público                  |
| POST   | /login                    | Público                  |
| POST   | /bicicletas/registrar     | Autenticado               |
| GET    | /bicicletas/mias          | Autenticado               |
| GET    | /disponibilidad           | Público                  |
| POST   | /ingresos/registrar       | Vigilante, Administrador |
| POST   | /salidas/registrar        | Vigilante, Administrador |
| POST   | /reservas/crear           | Usuario                   |
| GET    | /reservas/mia             | Usuario                   |
| POST   | /incidentes/registrar     | Vigilante, Administrador |
| GET    | /reportes/generar         | Administrador             |

## Arquitectura por capas y patrones de diseño
- `database.py` → capa de Acceso a Datos + patrón **Singleton** (pool único).
- `dao.py` → capa de Acceso a Datos + patrón **DAO/Repository**.
- `schemas.py` → capa de Modelo (Pydantic).
- `patterns.py` → patrones **Factory** (creación de usuarios), **Strategy**
  (exportación JSON/CSV/PDF de reportes) y **Observer** (notificación de
  eventos de disponibilidad/expiración de reservas).
- `security.py` → hashing bcrypt + JWT (sesión de 30 min, RF-02, RNF03).
- `main.py` → capa de Presentación/Controller (endpoints FastAPI + reglas
  de negocio RN-01 a RN-09).

## Paleta visual "Medellín"
Verde montaña `#1B6B3C`, magenta `#D6007F`, naranja `#FF6B00`, turquesa
`#00A8A0` y amarillo `#FFC800`, aplicados en el fondo degradado, la barra de
navegación y los acentos de cada tarjeta funcional.

## Conexión desde MySQL Workbench
- Host: `127.0.0.1`
- Puerto: `3307`
- Usuario: `root`
- Contraseña: `root`
- Base de datos: `ParqueaderoBicicletas`
'@
Set-Content -Path "README.md" -Value $contenido -Encoding UTF8 -NoNewline
Write-Host "  OK -> README.md" -ForegroundColor Green

Write-Host ""
Write-Host "Listo. Los 13 archivos fueron creados/actualizados." -ForegroundColor Cyan
Write-Host "Siguiente paso: docker compose down -v ; docker compose up -d --build" -ForegroundColor Yellow