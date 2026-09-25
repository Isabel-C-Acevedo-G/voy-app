"""
Sistema Web para la Gestión de Parqueaderos de Bicicletas en Medellín
Backend - FastAPI + MySQL
Arquitectura por Capas: Presentación, Lógica de Negocio, Acceso a Datos

CORRECCIONES APLICADAS respecto a la versión anterior:
1. /auth/register ya NO permite que el cliente se autoasigne 'Administrador'.
2. /reportes/generar ahora sí verifica el rol (antes el chequeo estaba roto
   por usar Depends(lambda: ...), que nunca ejecutaba la validación real).
3. El token JWT ahora respeta ACCESS_TOKEN_EXPIRE_MINUTES (8 horas) en vez
   de quedarse silenciosamente en el valor por defecto de 15 minutos.
4. Se eliminó el bloque de seguridad duplicado y la función require_role
   duplicada con código inalcanzable.
5. El registro ya no asume que el rol 'Ciclista' tiene siempre IdRol = 3;
   se busca por nombre.
6. Se agregaron restricciones de rol por endpoint (antes solo se exigía
   estar autenticado, sin importar el rol, en ingresos/salidas/reservas/
   incidentes).
7. /reservas/crear ahora reserva SIEMPRE a nombre del usuario autenticado
   (antes el cliente podía mandar el documento de otra persona) y valida
   que la bicicleta le pertenezca.
8. Se agregaron endpoints de registro de bicicleta (/bicicletas/registrar,
   /bicicletas/mias), necesarios para que Reservas e Ingresos funcionen
   sin que el vigilante tenga que crear la bicicleta "al vuelo".
"""

import os
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field, field_validator
import mysql.connector
from mysql.connector import Error
from passlib.context import CryptContext
from jose import JWTError, jwt
import asyncio

# ==================== CONFIGURACIÓN ====================

APP_CONFIG = {
    "TITLE": "Parqueadero Bicicletas Medellín",
    "VERSION": "1.1.0",
    "DESCRIPTION": "Sistema de gestión de parqueaderos de bicicletas - Medellín",
    "SECRET_KEY": os.getenv("SECRET_KEY", "tu_clave_secreta_muy_segura_2024"),
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": 60 * 8,  # 8 horas
}

# Paleta "Medellín" (informativa; el frontend ya la usa directamente en su CSS)
MEDELLIN_COLORS = {
    "verde_montana": "#00A650",
    "magenta": "#D6007F",
    "naranja": "#FF8C00",
    "turquesa": "#40E0D0",
    "amarillo": "#FFD700",
}

# Roles que un usuario puede autoasignarse desde el registro público.
# 'Administrador' queda deliberadamente fuera: se promueve solo por SQL
# o por un endpoint futuro protegido, nunca desde /auth/register.
ROLES_PUBLICOS_PERMITIDOS = {"Ciclista", "Vigilante"}
ROL_POR_DEFECTO = "Ciclista"

# ==================== MODELOS PYDANTIC ====================


class TokenData(BaseModel):
    sub: str
    rol: str
    exp: datetime


class CredencialesLogin(BaseModel):
    usuario: str = Field(..., min_length=1, description="Correo o documento")
    contrasena: str = Field(..., min_length=6, description="Contraseña")


class RegistroUsuario(BaseModel):
    documento: str = Field(..., min_length=5, max_length=20)
    nombres: str = Field(..., min_length=3, max_length=100)
    apellidos: str = Field(..., min_length=3, max_length=100)
    correo: EmailStr
    telefono: Optional[str] = Field(None, max_length=20)
    contrasena: str = Field(..., min_length=8)
    rol: str = "Ciclista"

    @field_validator("documento")
    @classmethod
    def documento_valido(cls, v):
        if not v.strip():
            raise ValueError("El documento no puede estar vacío")
        return v.strip()


class BicicletaCreate(BaseModel):
    marca: Optional[str] = Field(None, max_length=50)
    modelo: Optional[str] = Field(None, max_length=50)
    color: Optional[str] = Field(None, max_length=30)
    numero_serie: str = Field(..., max_length=100)


class MovimientoIngreso(BaseModel):
    documento_usuario: str = Field(..., description="Documento del usuario")
    numero_serie_bici: Optional[str] = Field(None, description="Número de serie de la bicicleta")


class MovimientoSalida(BaseModel):
    documento_usuario: str = Field(..., description="Documento del usuario")


class ReservaCreate(BaseModel):
    # El documento ya NO se recibe del cliente: la reserva siempre se hace
    # a nombre del usuario autenticado (ver corrección nº7 arriba).
    numero_serie_bici: str


class IncidenteCreate(BaseModel):
    id_usuario: Optional[int] = None
    id_bicicleta: Optional[int] = None
    tipo_incidente: str = Field(..., max_length=100)
    descripcion: str = Field(..., min_length=10)


class ReporteFiltro(BaseModel):
    fecha_inicio: datetime
    fecha_fin: datetime
    tipo: str = Field(..., pattern="^(movimientos|incidentes|todos)$")


# ==================== SEGURIDAD ====================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hashea una contraseña usando bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica una contraseña contra su hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Crea un token JWT. Si no se pasa expires_delta, usa el valor
    configurado en APP_CONFIG (8 horas) — antes se usaba un valor por
    defecto de 15 minutos que ignoraba esa configuración.
    """
    to_encode = data.copy()
    expira_en = expires_delta or timedelta(minutes=APP_CONFIG["ACCESS_TOKEN_EXPIRE_MINUTES"])
    expire = datetime.utcnow() + expira_en
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, APP_CONFIG["SECRET_KEY"], algorithm=APP_CONFIG["ALGORITHM"])


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> TokenData:
    """Obtiene el usuario actual a partir del token JWT."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se proporcionaron credenciales",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, APP_CONFIG["SECRET_KEY"], algorithms=[APP_CONFIG["ALGORITHM"]])
        return TokenData(sub=payload["sub"], rol=payload["rol"], exp=datetime.fromtimestamp(payload["exp"]))
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )


def rol_requerido(*roles_permitidos: str):
    """
    Fábrica de dependencias de FastAPI para restringir un endpoint a
    ciertos roles. Sustituye al antiguo patrón roto
    Depends(lambda: require_role([...])), que nunca resolvía current_user
    de verdad porque la lambda no es awaited por FastAPI.
    """

    async def _verificador(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if current_user.rol not in roles_permitidos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rol no autorizado. Se requiere: {', '.join(roles_permitidos)}",
            )
        return current_user

    return _verificador


# ==================== BASE DE DATOS ====================


@contextmanager
def get_db_connection():
    """Context manager para conexiones a MySQL."""
    conn = None
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_SERVER", "mysql"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_UID", "root"),
            password=os.getenv("DB_PWD", "root"),
            database=os.getenv("DB_DATABASE", "ParqueaderoBicicletas"),
            autocommit=False,
            connection_timeout=10,
            charset="utf8mb4",
            use_pure=True,
        )
        yield conn
    except Error as e:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Error de conexión a la base de datos: {str(e)}",
        )
    finally:
        if conn and conn.is_connected():
            conn.close()


# ==================== SERVICIOS DE NEGOCIO ====================


class ParqueaderoService:
    """Servicio para la lógica de negocio del parqueadero."""

    @staticmethod
    def obtener_espacio_disponible(conn) -> Optional[int]:
        cursor = conn.cursor()
        cursor.execute("SELECT IdEspacio FROM Espacios WHERE Estado = 'Disponible' LIMIT 1")
        resultado = cursor.fetchone()
        cursor.close()
        return resultado[0] if resultado else None

    @staticmethod
    def verificar_ingreso_activo(conn, id_usuario: int) -> bool:
        """RN-02: Verifica si el usuario ya tiene un ingreso activo."""
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*)
            FROM Ingresos i
            LEFT JOIN Salidas s ON i.IdIngreso = s.IdIngreso
            WHERE i.IdUsuario = %s AND s.IdSalida IS NULL
            """,
            (id_usuario,),
        )
        count = cursor.fetchone()[0]
        cursor.close()
        return count > 0

    @staticmethod
    def obtener_ingreso_activo(conn, id_usuario: int) -> Optional[dict]:
        """RN-03: Obtiene el ingreso activo de un usuario."""
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT i.IdIngreso, i.IdEspacio, i.FechaIngreso
            FROM Ingresos i
            LEFT JOIN Salidas s ON i.IdIngreso = s.IdIngreso
            WHERE i.IdUsuario = %s AND s.IdSalida IS NULL
            ORDER BY i.FechaIngreso DESC
            LIMIT 1
            """,
            (id_usuario,),
        )
        resultado = cursor.fetchone()
        cursor.close()
        return resultado

    @staticmethod
    def contar_cupos(conn) -> dict:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM Espacios WHERE Estado = 'Disponible'")
        libres = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM Espacios WHERE Estado = 'Ocupado'")
        ocupados = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM Espacios WHERE Estado = 'Reservado'")
        reservados = cursor.fetchone()[0]
        cursor.close()
        return {
            "cupos_libres": libres,
            "cupos_ocupados": ocupados,
            "cupos_reservados": reservados,
            "total_cupos": libres + ocupados + reservados,
        }


# ==================== TAREAS EN SEGUNDO PLANO ====================


async def expirar_reservas_task():
    """RN-05: Tarea en segundo plano para expirar reservas > 30 min."""
    while True:
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE Espacios e
                    INNER JOIN Reservas r ON e.IdEspacio = r.IdEspacio
                    SET e.Estado = 'Disponible'
                    WHERE r.Estado = 'Activa' AND r.FechaExpiracion < NOW()
                    """
                )
                cursor.execute(
                    """
                    UPDATE Reservas
                    SET Estado = 'Expirada'
                    WHERE Estado = 'Activa' AND FechaExpiracion < NOW()
                    """
                )
                reservas_expiradas = cursor.rowcount
                conn.commit()
                cursor.close()
                if reservas_expiradas > 0:
                    print(f"[reservas] {reservas_expiradas} reserva(s) expiradas automáticamente")
        except Exception as e:
            print(f"[reservas] Error en tarea de expiración: {e}")
        await asyncio.sleep(60)


# ==================== APP FASTAPI ====================

app = FastAPI(
    title=APP_CONFIG["TITLE"],
    version=APP_CONFIG["VERSION"],
    description=APP_CONFIG["DESCRIPTION"],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    print("Iniciando sistema de parqueadero...")
    asyncio.create_task(expirar_reservas_task())


# ==================== ENDPOINTS DE AUTENTICACIÓN ====================


@app.post("/auth/login", tags=["Autenticación"])
async def login(credenciales: CredencialesLogin):
    """RF-01: Inicio de sesión con verificación de contraseña encriptada."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT U.IdUsuario, U.PasswordHash, U.Nombres, U.Apellidos,
                   R.NombreRol, U.Documento, U.Estado
            FROM Usuarios U
            INNER JOIN Roles R ON U.IdRol = R.IdRol
            WHERE U.Correo = %s OR U.Documento = %s
            """,
            (credenciales.usuario, credenciales.usuario),
        )
        resultado = cursor.fetchone()
        cursor.close()

        if not resultado:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario o contraseña incorrectos")

        id_usuario, password_hash, nombres, apellidos, rol, documento, estado = resultado

        if not verify_password(credenciales.contrasena, password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario o contraseña incorrectos")

        if estado != "Activo":
            # RN-08: usuarios desactivados no pueden iniciar sesión.
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Esta cuenta está desactivada.")

        access_token = create_access_token(data={"sub": documento, "rol": rol})

        return {
            "status": "success",
            "mensaje": "Acceso verificado correctamente",
            "access_token": access_token,
            "token_type": "bearer",
            "expira_minutos": APP_CONFIG["ACCESS_TOKEN_EXPIRE_MINUTES"],
            "usuario": {
                "documento": documento,
                "nombres": nombres,
                "apellidos": apellidos,
                "rol": rol,
            },
        }


@app.post("/auth/register", tags=["Autenticación"])
async def register(usuario: RegistroUsuario):
    """
    RF-02: Registro de nuevos usuarios.

    CORRECCIÓN DE SEGURIDAD: antes, el campo 'rol' enviado por el cliente
    se usaba sin validar, así que cualquiera podía registrarse como
    'Administrador'. Ahora solo se acepta 'Ciclista' o 'Vigilante'; cualquier
    otro valor (incluido 'Administrador') se degrada a 'Ciclista'.
    """
    rol_solicitado = usuario.rol if usuario.rol in ROLES_PUBLICOS_PERMITIDOS else ROL_POR_DEFECTO

    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT IdUsuario FROM Usuarios WHERE Documento = %s OR Correo = %s",
            (usuario.documento, usuario.correo),
        )
        if cursor.fetchone():
            cursor.close()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El documento o correo ya está registrado")

        # CORRECCIÓN: se busca el rol por nombre, nunca se asume un ID fijo.
        cursor.execute("SELECT IdRol FROM Roles WHERE NombreRol = %s", (rol_solicitado,))
        rol_db = cursor.fetchone()
        if not rol_db:
            cursor.execute("SELECT IdRol FROM Roles WHERE NombreRol = %s", (ROL_POR_DEFECTO,))
            rol_db = cursor.fetchone()
        id_rol = rol_db[0]

        cursor.execute(
            """
            INSERT INTO Usuarios (Documento, Nombres, Apellidos, Correo, Telefono, PasswordHash, IdRol)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                usuario.documento,
                usuario.nombres,
                usuario.apellidos,
                usuario.correo,
                usuario.telefono,
                hash_password(usuario.contrasena),
                id_rol,
            ),
        )
        conn.commit()
        cursor.close()

        return {"status": "success", "mensaje": "Usuario registrado correctamente"}


# ==================== ENDPOINTS DE BICICLETAS ====================


@app.post("/bicicletas/registrar", tags=["Bicicletas"], status_code=status.HTTP_201_CREATED)
async def registrar_bicicleta(
    bici: BicicletaCreate, current_user: TokenData = Depends(get_current_user)
):
    """RF-03: Registrar una bicicleta a nombre del usuario autenticado."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT IdUsuario FROM Usuarios WHERE Documento = %s", (current_user.sub,))
        usuario_result = cursor.fetchone()
        if not usuario_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
        id_usuario = usuario_result[0]

        cursor.execute("SELECT IdBicicleta FROM Bicicletas WHERE NumeroSerie = %s", (bici.numero_serie,))
        if cursor.fetchone():
            cursor.close()
            # RN-01: número de serie único.
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ya existe una bicicleta con ese número de serie")

        cursor.execute(
            """
            INSERT INTO Bicicletas (IdUsuario, Marca, Modelo, Color, NumeroSerie, Estado)
            VALUES (%s, %s, %s, %s, %s, 'Activa')
            """,
            (id_usuario, bici.marca, bici.modelo, bici.color, bici.numero_serie),
        )
        conn.commit()
        id_bicicleta = cursor.lastrowid
        cursor.close()

        return {"status": "success", "mensaje": "Bicicleta registrada correctamente", "id_bicicleta": id_bicicleta}


@app.get("/bicicletas/mias", tags=["Bicicletas"])
async def mis_bicicletas(current_user: TokenData = Depends(get_current_user)):
    """Lista las bicicletas del usuario autenticado."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT IdUsuario FROM Usuarios WHERE Documento = %s", (current_user.sub,))
        usuario_result = cursor.fetchone()
        if not usuario_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

        cursor.execute(
            "SELECT * FROM Bicicletas WHERE IdUsuario = %s AND Estado = 'Activa'",
            (usuario_result["IdUsuario"],),
        )
        bicicletas = cursor.fetchall()
        cursor.close()
        return {"status": "success", "datos": bicicletas}


# ==================== ENDPOINTS DE INGRESOS ====================


@app.post("/ingresos/registrar", tags=["Ingresos"], status_code=status.HTTP_201_CREATED)
async def registrar_ingreso(
    movimiento: MovimientoIngreso,
    current_user: TokenData = Depends(rol_requerido("Vigilante", "Administrador")),
):
    """
    CU-01: Registrar ingreso de bicicleta.
    RN-02: Validar que no tenga ingreso activo previo.
    RN-04: Validar disponibilidad de cupos y asignar espacio.
    Restringido a Vigilante/Administrador (antes cualquier rol autenticado
    podía llamar a este endpoint).
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT IdUsuario FROM Usuarios WHERE Documento = %s", (movimiento.documento_usuario,))
        usuario_result = cursor.fetchone()
        if not usuario_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
        id_usuario = usuario_result[0]

        if ParqueaderoService.verificar_ingreso_activo(conn, id_usuario):
            cursor.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="RN-02: El usuario ya tiene un ingreso activo. Debe registrar la salida primero.",
            )

        id_bicicleta = None
        if movimiento.numero_serie_bici:
            cursor.execute(
                "SELECT IdBicicleta FROM Bicicletas WHERE NumeroSerie = %s AND IdUsuario = %s",
                (movimiento.numero_serie_bici, id_usuario),
            )
            bici_result = cursor.fetchone()
            if not bici_result:
                cursor.close()
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Esa bicicleta no está registrada a nombre de este usuario. Regístrela primero en /bicicletas/registrar.",
                )
            id_bicicleta = bici_result[0]

        # ¿Tiene una reserva activa? Si sí, se convierte en ingreso (RN-06) usando el mismo espacio.
        cursor.execute(
            "SELECT IdReserva, IdEspacio FROM Reservas WHERE IdUsuario = %s AND Estado = 'Activa' LIMIT 1",
            (id_usuario,),
        )
        reserva_activa = cursor.fetchone()

        if reserva_activa:
            id_reserva, id_espacio = reserva_activa
            cursor.execute("UPDATE Reservas SET Estado = 'Convertida' WHERE IdReserva = %s", (id_reserva,))
        else:
            id_espacio = ParqueaderoService.obtener_espacio_disponible(conn)
            if not id_espacio:
                cursor.close()
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="RN-04: No hay cupos disponibles en el parqueadero")

        cursor.execute(
            "INSERT INTO Ingresos (IdBicicleta, IdUsuario, IdEspacio, FechaIngreso) VALUES (%s, %s, %s, NOW())",
            (id_bicicleta, id_usuario, id_espacio),
        )
        id_ingreso = cursor.lastrowid

        cursor.execute("UPDATE Espacios SET Estado = 'Ocupado' WHERE IdEspacio = %s", (id_espacio,))

        conn.commit()
        cursor.close()

        return {
            "status": "success",
            "mensaje": "Ingreso registrado exitosamente",
            "datos": {
                "id_ingreso": id_ingreso,
                "id_espacio": id_espacio,
                "fecha_ingreso": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        }


# ==================== ENDPOINTS DE SALIDAS ====================


@app.post("/salidas/registrar", tags=["Salidas"])
async def registrar_salida(
    movimiento: MovimientoSalida,
    current_user: TokenData = Depends(rol_requerido("Vigilante", "Administrador")),
):
    """CU-02: Registrar salida de bicicleta. RN-03: exige ingreso activo previo."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT IdUsuario FROM Usuarios WHERE Documento = %s", (movimiento.documento_usuario,))
        usuario_result = cursor.fetchone()
        if not usuario_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
        id_usuario = usuario_result[0]

        ingreso_activo = ParqueaderoService.obtener_ingreso_activo(conn, id_usuario)
        if not ingreso_activo:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="RN-03: No se encontró un ingreso activo para este usuario")

        id_ingreso = ingreso_activo["IdIngreso"]
        id_espacio = ingreso_activo["IdEspacio"]

        cursor.execute("INSERT INTO Salidas (IdIngreso, FechaSalida) VALUES (%s, NOW())", (id_ingreso,))
        cursor.execute("UPDATE Espacios SET Estado = 'Disponible' WHERE IdEspacio = %s", (id_espacio,))

        conn.commit()
        cursor.close()

        return {
            "status": "success",
            "mensaje": "Salida registrada exitosamente",
            "datos": {
                "id_ingreso": id_ingreso,
                "id_espacio": id_espacio,
                "fecha_salida": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        }


# ==================== ENDPOINTS DE DISPONIBILIDAD ====================


@app.get("/disponibilidad", tags=["Disponibilidad"])
async def obtener_disponibilidad():
    """RF-06: Disponibilidad de cupos en tiempo real. Endpoint público."""
    with get_db_connection() as conn:
        conteo = ParqueaderoService.contar_cupos(conn)
        return {"status": "success", "datos": conteo, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}


# ==================== ENDPOINTS DE RESERVAS ====================


@app.post("/reservas/crear", tags=["Reservas"], status_code=status.HTTP_201_CREATED)
async def crear_reserva(
    reserva: ReservaCreate,
    current_user: TokenData = Depends(rol_requerido("Ciclista")),
):
    """
    RF-07: Crear reserva de espacio. RN-06: bloquea el espacio 30 minutos.
    CORRECCIÓN: la reserva ya no acepta un 'documento_usuario' en el body;
    siempre se hace a nombre del usuario autenticado (current_user), y se
    valida que la bicicleta indicada le pertenezca a él.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT IdUsuario FROM Usuarios WHERE Documento = %s", (current_user.sub,))
        usuario_result = cursor.fetchone()
        if not usuario_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
        id_usuario = usuario_result[0]

        cursor.execute("SELECT IdReserva FROM Reservas WHERE IdUsuario = %s AND Estado = 'Activa'", (id_usuario,))
        if cursor.fetchone():
            cursor.close()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ya tienes una reserva activa")

        cursor.execute(
            "SELECT IdBicicleta FROM Bicicletas WHERE NumeroSerie = %s AND IdUsuario = %s",
            (reserva.numero_serie_bici, id_usuario),
        )
        bici_result = cursor.fetchone()
        if not bici_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Esa bicicleta no está registrada a tu nombre")
        id_bicicleta = bici_result[0]

        id_espacio = ParqueaderoService.obtener_espacio_disponible(conn)
        if not id_espacio:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No hay espacios disponibles para reservar")

        fecha_expiracion = datetime.now() + timedelta(minutes=30)
        cursor.execute(
            """
            INSERT INTO Reservas (IdUsuario, IdBicicleta, IdEspacio, FechaReserva, FechaExpiracion, Estado)
            VALUES (%s, %s, %s, NOW(), %s, 'Activa')
            """,
            (id_usuario, id_bicicleta, id_espacio, fecha_expiracion),
        )
        cursor.execute("UPDATE Espacios SET Estado = 'Reservado' WHERE IdEspacio = %s", (id_espacio,))

        conn.commit()
        cursor.close()

        return {
            "status": "success",
            "mensaje": "Reserva creada exitosamente",
            "datos": {
                "id_espacio": id_espacio,
                "fecha_expiracion": fecha_expiracion.strftime("%Y-%m-%d %H:%M:%S"),
                "duracion_minutos": 30,
            },
        }


@app.get("/reservas/mia", tags=["Reservas"])
async def mi_reserva(current_user: TokenData = Depends(rol_requerido("Ciclista"))):
    """Devuelve la reserva activa del usuario autenticado, si tiene una."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT IdUsuario FROM Usuarios WHERE Documento = %s", (current_user.sub,))
        usuario_result = cursor.fetchone()
        if not usuario_result:
            cursor.close()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

        cursor.execute(
            """
            SELECT R.*, E.CodigoEspacio FROM Reservas R
            INNER JOIN Espacios E ON E.IdEspacio = R.IdEspacio
            WHERE R.IdUsuario = %s AND R.Estado = 'Activa'
            """,
            (usuario_result["IdUsuario"],),
        )
        reserva = cursor.fetchone()
        cursor.close()
        return {"status": "success", "reserva": reserva}


# ==================== ENDPOINTS DE INCIDENTES ====================


@app.post("/incidentes/registrar", tags=["Incidentes"], status_code=status.HTTP_201_CREATED)
async def registrar_incidente(
    incidente: IncidenteCreate,
    current_user: TokenData = Depends(rol_requerido("Vigilante", "Administrador")),
):
    """RF-08: Registrar incidente o novedad. Restringido a Vigilante/Administrador."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO Incidentes (IdUsuario, IdBicicleta, TipoIncidente, Descripcion, FechaIncidente)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (incidente.id_usuario, incidente.id_bicicleta, incidente.tipo_incidente, incidente.descripcion),
        )
        conn.commit()
        cursor.close()
        return {"status": "success", "mensaje": "Incidente registrado correctamente"}


@app.get("/incidentes", tags=["Incidentes"])
async def listar_incidentes(current_user: TokenData = Depends(rol_requerido("Administrador", "Vigilante"))):
    """Listar todos los incidentes (solo administradores y vigilantes)."""
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT i.*, u.Nombres, u.Apellidos, u.Documento
            FROM Incidentes i
            LEFT JOIN Usuarios u ON i.IdUsuario = u.IdUsuario
            ORDER BY i.FechaIncidente DESC
            """
        )
        incidentes = cursor.fetchall()
        cursor.close()
        return {"status": "success", "datos": incidentes, "total": len(incidentes)}


# ==================== ENDPOINTS DE REPORTES ====================


@app.post("/reportes/generar", tags=["Reportes"])
async def generar_reporte(
    filtro: ReporteFiltro,
    current_user: TokenData = Depends(rol_requerido("Administrador")),
):
    """
    CU-05, RF-10: Generar reportes para exportación. Solo Administrador.

    CORRECCIÓN CRÍTICA: antes se usaba
    Depends(lambda: require_role(["Administrador"])), que NO ejecutaba la
    validación de rol de verdad (la lambda nunca era awaited por FastAPI de
    la forma correcta). Ahora usa Depends(rol_requerido("Administrador")),
    el patrón correcto de dependencia parametrizada.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(dictionary=True)

        movimientos, incidentes = [], []

        if filtro.tipo in ("movimientos", "todos"):
            cursor.execute(
                """
                SELECT
                    i.IdIngreso, u.Documento,
                    CONCAT(u.Nombres, ' ', u.Apellidos) AS NombreUsuario,
                    b.NumeroSerie, b.Marca, b.Modelo, e.CodigoEspacio,
                    i.FechaIngreso, s.FechaSalida,
                    TIMESTAMPDIFF(MINUTE, i.FechaIngreso, COALESCE(s.FechaSalida, NOW())) AS DuracionMinutos
                FROM Ingresos i
                INNER JOIN Usuarios u ON i.IdUsuario = u.IdUsuario
                LEFT JOIN Bicicletas b ON i.IdBicicleta = b.IdBicicleta
                INNER JOIN Espacios e ON i.IdEspacio = e.IdEspacio
                LEFT JOIN Salidas s ON i.IdIngreso = s.IdIngreso
                WHERE i.FechaIngreso BETWEEN %s AND %s
                ORDER BY i.FechaIngreso DESC
                """,
                (filtro.fecha_inicio, filtro.fecha_fin),
            )
            movimientos = cursor.fetchall()

        if filtro.tipo in ("incidentes", "todos"):
            cursor.execute(
                """
                SELECT
                    inc.*, u.Documento,
                    CONCAT(u.Nombres, ' ', u.Apellidos) AS NombreUsuario,
                    b.NumeroSerie AS BicicletaNumeroSerie
                FROM Incidentes inc
                LEFT JOIN Usuarios u ON inc.IdUsuario = u.IdUsuario
                LEFT JOIN Bicicletas b ON inc.IdBicicleta = b.IdBicicleta
                WHERE inc.FechaIncidente BETWEEN %s AND %s
                ORDER BY inc.FechaIncidente DESC
                """,
                (filtro.fecha_inicio, filtro.fecha_fin),
            )
            incidentes = cursor.fetchall()

        cursor.close()

        # Serializar fechas/timedeltas para que el JSON sea válido.
        def _serializar(fila):
            return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in fila.items()}

        return {
            "status": "success",
            "mensaje": "Reporte generado exitosamente",
            "datos": {
                "metadata": {
                    "titulo": "Reporte de Parqueadero",
                    "fecha_generacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "filtro": {
                        "fecha_inicio": filtro.fecha_inicio.isoformat(),
                        "fecha_fin": filtro.fecha_fin.isoformat(),
                        "tipo": filtro.tipo,
                    },
                },
                "movimientos": [_serializar(m) for m in movimientos],
                "incidentes": [_serializar(i) for i in incidentes],
                "resumen": {"total_movimientos": len(movimientos), "total_incidentes": len(incidentes)},
            },
        }


# ==================== ENDPOINTS DE INFORMACIÓN ====================


@app.get("/", tags=["Información"])
async def root():
    return {
        "sistema": APP_CONFIG["TITLE"],
        "version": APP_CONFIG["VERSION"],
        "descripcion": APP_CONFIG["DESCRIPTION"],
        "colores_medellin": MEDELLIN_COLORS,
        "documentacion": "/docs",
    }


@app.get("/health", tags=["Salud"])
async def health_check():
    try:
        with get_db_connection() as conn:
            if conn.is_connected():
                return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)