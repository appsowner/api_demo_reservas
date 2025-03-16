from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from uuid import uuid4
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import jwt
from functools import wraps
from flask_swagger_ui import get_swaggerui_blueprint

# Cargar variables de entorno
load_dotenv()

# Configuración desde variables de entorno
PORT = int(os.getenv("PORT", 5000))
DEBUG = os.getenv("DEBUG", "True").lower() == "true"
HOST = os.getenv("HOST", "0.0.0.0")
SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_predeterminada")
TOKEN_EXPIRATION = int(os.getenv("TOKEN_EXPIRATION", 3600))  # 1 hora por defecto

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(app, resources={r"/api/*": {"origins": "http://appsowner.app"}})

# Configuración de Swagger
SWAGGER_URL = "/swagger"  # URL donde se servirá la interfaz de Swagger
API_URL = "/static/swagger.json"  # Ruta al archivo swagger.json (debes crearlo)

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL, API_URL, config={"app_name": "API de Reservas Médicas"}
)

# Registrar el blueprint de Swagger
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)


# Credenciales de usuarios (en producción deberías usar una base de datos)
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "medico": {"password": "medico123", "role": "medico"},
    "recepcion": {"password": "recepcion123", "role": "recepcion"},
}

# Base de datos simulada (en producción usarías una BD real)
pacientes = {
    "12345678-9": {
        "id": "12345678-9",
        "nombre": "Juan Pérez",
        "email": "juan.perez@ejemplo.cl",
        "telefono": "+56912345678",
    },
    "98765432-1": {
        "id": "98765432-1",
        "nombre": "María González",
        "email": "maria.gonzalez@ejemplo.cl",
        "telefono": "+56987654321",
    },
}

examenes = {
    "E001": {"id": "E001", "nombre": "Hemograma", "duracion": 15},
    "E002": {"id": "E002", "nombre": "Perfil Bioquímico", "duracion": 20},
    "E003": {"id": "E003", "nombre": "Radiografía Tórax", "duracion": 30},
    "E004": {"id": "E004", "nombre": "Ecografía Abdominal", "duracion": 45},
}

doctores = {
    "D001": {
        "id": "D001",
        "nombre": "Dr. Rodrigo Silva",
        "especialidad": "Medicina General",
    },
    "D002": {
        "id": "D002",
        "nombre": "Dra. Carolina Muñoz",
        "especialidad": "Cardiología",
    },
    "D003": {"id": "D003", "nombre": "Dr. Felipe Rojas", "especialidad": "Neurología"},
}

especialidades = [
    "Medicina General",
    "Cardiología",
    "Neurología",
    "Dermatología",
    "Pediatría",
]

# Reservas de exámenes
reservas_examenes = [
    {
        "id": "RE001",
        "paciente_id": "12345678-9",
        "examenes": ["E001", "E002"],
        "fecha": "2025-03-20",
        "hora": "09:00",
        "estado": "confirmada",
        "centro_medico": "Clínica Las Condes",
        "notas": "Paciente debe venir en ayunas",
    },
    {
        "id": "RE002",
        "paciente_id": "98765432-1",
        "examenes": ["E003", "E004"],
        "fecha": "2025-03-22",
        "hora": "11:30",
        "estado": "pendiente",
        "centro_medico": "Hospital del Trabajador",
        "notas": "",
    },
]

# Reservas de consultas médicas
reservas_consultas = [
    {
        "id": "RC001",
        "paciente_id": "12345678-9",
        "doctor_id": "D002",
        "especialidad": "Cardiología",
        "fecha": "2025-03-25",
        "hora": "16:00",
        "estado": "confirmada",
        "centro_medico": "Clínica Santa María",
        "motivo": "Control anual",
        "notas": "Traer exámenes previos",
    },
    {
        "id": "RC002",
        "paciente_id": "98765432-1",
        "doctor_id": "D001",
        "especialidad": "Medicina General",
        "fecha": "2025-03-18",
        "hora": "10:30",
        "estado": "atendida",
        "centro_medico": "CESFAM La Florida",
        "motivo": "Consulta por dolor abdominal",
        "notas": "",
    },
]


# Función decoradora para verificar token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Verificar si hay encabezado de autorización
        auth_header = request.headers.get("Authorization")
        if auth_header:
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Token no proporcionado"}), 401

        try:
            # Decodificar token
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = data["username"]
            current_role = data["role"]
        except jwt.ExpiredSignatureError:
            return (
                jsonify(
                    {"message": "Token expirado. Por favor inicie sesión nuevamente"}
                ),
                401,
            )
        except:
            return jsonify({"message": "Token inválido"}), 401

        # Pasar información del usuario a la función
        return f(current_user, current_role, *args, **kwargs)

    return decorated


# Función para generar nuevos IDs
def generar_id(prefijo="ID"):
    return f"{prefijo}-{str(uuid4())[:8]}"


# Ruta de login para obtener token
@app.route("/api/login", methods=["POST"])
def login():
    auth = request.json

    if not auth or not auth.get("username") or not auth.get("password"):
        return make_response(
            "No se pudo verificar",
            401,
            {"WWW-Authenticate": 'Bearer realm="Login requerido"'},
        )

    username = auth.get("username")
    password = auth.get("password")

    if username not in users or users[username]["password"] != password:
        return make_response(
            "Credenciales inválidas",
            401,
            {"WWW-Authenticate": 'Bearer realm="Credenciales inválidas"'},
        )

    # Si las credenciales son correctas, generamos el token
    token_data = {
        "username": username,
        "role": users[username]["role"],
        "exp": datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRATION),
    }

    token = jwt.encode(token_data, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify(
        {
            "token": token,
            "expires_in": TOKEN_EXPIRATION,
            "token_type": "Bearer",
            "user": {"username": username, "role": users[username]["role"]},
        }
    )


# API para reservas de exámenes
@app.route("/api/reservas/examenes", methods=["GET"])
@token_required
def obtener_reservas_examenes(current_user, current_role):
    # Opción de filtrar por paciente
    paciente_id = request.args.get("paciente_id")

    if paciente_id:
        # Filtrar reservas por el ID del paciente
        reservas_filtradas = [
            r for r in reservas_examenes if r["paciente_id"] == paciente_id
        ]
        return jsonify(reservas_filtradas)

    # Si no hay filtro, devolver todas las reservas
    return jsonify(reservas_examenes)


@app.route("/api/reservas/examenes/<string:id>", methods=["GET"])
@token_required
def obtener_reserva_examen(current_user, current_role, id):
    # Buscar reserva por ID
    reserva = next((r for r in reservas_examenes if r["id"] == id), None)

    if reserva:
        # Obtener detalles de paciente y exámenes
        resultado = reserva.copy()

        # Agregar información del paciente
        if reserva["paciente_id"] in pacientes:
            resultado["paciente"] = pacientes[reserva["paciente_id"]]

        # Agregar información de los exámenes
        examenes_detalle = []
        for examen_id in reserva["examenes"]:
            if examen_id in examenes:
                examenes_detalle.append(examenes[examen_id])

        resultado["examenes_detalle"] = examenes_detalle

        return jsonify(resultado)

    return jsonify({"error": "Reserva no encontrada"}), 404


# API para reservas de consultas médicas
@app.route("/api/reservas/consultas", methods=["GET"])
@token_required
def obtener_reservas_consultas(current_user, current_role):
    # Opciones de filtro
    paciente_id = request.args.get("paciente_id")
    doctor_id = request.args.get("doctor_id")
    especialidad = request.args.get("especialidad")

    # Aplicar filtros
    reservas_filtradas = reservas_consultas

    if paciente_id:
        reservas_filtradas = [
            r for r in reservas_filtradas if r["paciente_id"] == paciente_id
        ]

    if doctor_id:
        reservas_filtradas = [
            r for r in reservas_filtradas if r["doctor_id"] == doctor_id
        ]

    if especialidad:
        reservas_filtradas = [
            r for r in reservas_filtradas if r["especialidad"] == especialidad
        ]

    return jsonify(reservas_filtradas)


@app.route("/api/reservas/consultas/<string:id>", methods=["GET"])
@token_required
def obtener_reserva_consulta(current_user, current_role, id):
    # Buscar reserva por ID
    reserva = next((r for r in reservas_consultas if r["id"] == id), None)

    if reserva:
        # Obtener detalles adicionales
        resultado = reserva.copy()

        # Agregar información del paciente
        if reserva["paciente_id"] in pacientes:
            resultado["paciente"] = pacientes[reserva["paciente_id"]]

        # Agregar información del doctor
        if reserva["doctor_id"] in doctores:
            resultado["doctor"] = doctores[reserva["doctor_id"]]

        return jsonify(resultado)

    return jsonify({"error": "Reserva no encontrada"}), 404


# Opcional: Endpoints adicionales para listar datos de referencia
@app.route("/api/pacientes", methods=["GET"])
@token_required
def listar_pacientes(current_user, current_role):
    # Solo admin y médicos pueden ver todos los pacientes
    if current_role not in ["admin", "medico"]:
        return jsonify({"error": "No autorizado"}), 403

    return jsonify(list(pacientes.values()))


@app.route("/api/examenes", methods=["GET"])
@token_required
def listar_examenes(current_user, current_role):
    return jsonify(list(examenes.values()))


@app.route("/api/doctores", methods=["GET"])
@token_required
def listar_doctores(current_user, current_role):
    return jsonify(list(doctores.values()))


@app.route("/api/especialidades", methods=["GET"])
@token_required
def listar_especialidades(current_user, current_role):
    return jsonify(especialidades)


# Ruta raíz para verificar que el servidor está funcionando
@app.route("/")
def index():
    return jsonify(
        {
            "estado": "en línea",
            "mensaje": "API de reservas médicas funcionando correctamente",
            "version": os.getenv("VERSION", "1.0.0"),
            "entorno": os.getenv("FLASK_ENV", "development"),
            "autenticacion": "Bearer Token JWT",
            "endpoints_disponibles": [
                "/api/login (POST - obtener token)",
                "/api/reservas/examenes (GET - protegido)",
                "/api/reservas/examenes/<id> (GET - protegido)",
                "/api/reservas/consultas (GET - protegido)",
                "/api/reservas/consultas/<id> (GET - protegido)",
                "/api/pacientes (GET - protegido, roles: admin, medico)",
                "/api/examenes (GET - protegido)",
                "/api/doctores (GET - protegido)",
                "/api/especialidades (GET - protegido)",
            ],
        }
    )


# Este bloque permite ejecutar la aplicación directamente sin necesidad
# de configurar la variable de entorno FLASK_APP
if __name__ == "__main__":
    print(
        f"Iniciando servidor API REST de reservas médicas en modo {'DEBUG' if DEBUG else 'PRODUCCIÓN'}"
    )
    print(f"Accede a http://{HOST}:{PORT}/ para verificar el funcionamiento")
    print(
        "Para obtener un token, realiza una petición POST a /api/login con las credenciales"
    )
    app.run(debug=DEBUG, host=HOST, port=PORT)
