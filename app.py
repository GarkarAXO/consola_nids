"""
Servidor web y API backend - Consola de gestión NIDS
Autor:

Este archivo coordina el funcionamiento de la consola de gestión para el sistema
de detección de intrusos. Se encarga de recibir los datos de tráfico y las alertas
que genera el motor de seguridad, mantener las estadísticas actualizadas en tiempo
real y proveer los servicios necesarios para que el usuario pueda supervisar la
red, consultar la bitácora y ajustar parámetros desde el navegador. Incorpora
control de autenticación administrativa, validación estricta de parámetros y
registro de auditoría para operaciones de mitigación.
"""

import collections
import csv
import functools
import io
import os
import secrets
import threading
import time
from datetime import datetime

import psutil
from flask import Flask, Response, jsonify, render_template, request, session

import firewall
import hids
import sniffer

app = Flask(__name__)
app.json.sort_keys = False

# Carga de variables de entorno mediante python-dotenv con respaldo nativo
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    for _archivo_env in (".env", "env"):
        if os.path.exists(_archivo_env):
            try:
                with open(_archivo_env, "r", encoding="utf-8") as _f_env:
                    for _linea in _f_env:
                        _linea = _linea.strip()
                        if _linea and not _linea.startswith("#") and "=" in _linea:
                            _k, _v = _linea.split("=", 1)
                            _k = _k.strip()
                            _v = _v.strip().strip('"').strip("'")
                            if _k not in os.environ:
                                os.environ[_k] = _v
            except Exception:
                pass

# Clave secreta para gestión de sesiones seguras (generada aleatoriamente si no se define en .env)
app.secret_key = os.environ.get("NIDS_SECRET_KEY") or secrets.token_hex(32)

# Credenciales administrativas y token de API leídos estrictamente desde el entorno o archivo .env
ADMIN_USUARIO = os.environ.get("NIDS_ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("NIDS_ADMIN_PASSWORD")
ADMIN_API_KEY = os.environ.get("NIDS_API_KEY")

lock = threading.Lock()

# Estado operativo y métricas en memoria
estado = {
    "conectado": False,
    "interfaz": None,
    "inicio": None,
    "paquetes": 0,
    "bytes": 0,
}
paquetes_recientes = collections.deque(maxlen=100)
alertas = collections.deque(maxlen=5000)
protocolos = collections.Counter()
origenes = collections.Counter()
serie_pps = collections.deque([0] * 60, maxlen=60)
_contador_segundo = 0

# Parámetros editables para el análisis del motor de detección
configuracion = {
    "ventana_seg": 10,
    "umbral_conexiones": 8,
    "umbral_pps": 300,
    "enfriamiento_seg": 20,
    "lista_blanca": "192.168.1.1",
    "notificar_severidad_minima": "baja",
}


def hora():
    """Retorna la hora actual del sistema en formato HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")


def sanitizar_campo_csv(valor):
    """
    Evita la inyección de fórmulas en hojas de cálculo (CSV Injection)
    anteponiendo un apóstrofe a textos que inicien con caracteres ejecutables.
    """
    texto = str(valor if valor is not None else "")
    if texto and texto[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + texto
    return texto


def requiere_autenticacion(f):
    """
    Restringe el acceso a endpoints administrativos verificando la existencia
    de una sesión activa en cookies o la cabecera X-API-Key / Bearer Token.
    """
    @functools.wraps(f)
    def decorada(*args, **kwargs):
        if session.get("usuario"):
            return f(*args, **kwargs)

        api_key = request.headers.get("X-API-Key")
        auth_header = request.headers.get("Authorization", "")
        token_bearer = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else ""

        if ADMIN_API_KEY and ((api_key and api_key == ADMIN_API_KEY) or (token_bearer and token_bearer == ADMIN_API_KEY)):
            return f(*args, **kwargs)

        return jsonify({
            "ok": False,
            "mensaje": "Acceso restringido. Se requiere autenticación como administrador.",
            "codigo": "NO_AUTORIZADO",
        }), 401
    return decorada


def obtener_actor_actual():
    """
    Identifica el nombre del usuario y la dirección IP que originó la petición.
    """
    usuario = session.get("usuario") or "Token-API"
    ip_origen = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
    return usuario, ip_origen


def registrar_paquete(p):
    """
    Recibe la información de un paquete analizado por el motor y actualiza
    los contadores de tráfico, protocolos y la lista de paquetes recientes.
    """
    global _contador_segundo
    with lock:
        estado["paquetes"] += 1
        estado["bytes"] += int(p.get("len", 0) or 0)
        _contador_segundo += 1
        protocolos[p.get("proto", "OTRO")] += 1
        if p.get("src"):
            origenes[p["src"]] += 1
        paquetes_recientes.appendleft({
            "hora": p.get("hora", hora()),
            "src": p.get("src", ""),
            "dst": p.get("dst", ""),
            "proto": p.get("proto", ""),
            "puerto": p.get("puerto", ""),
            "len": p.get("len", ""),
            "info": p.get("info", ""),
        })


def registrar_alerta(a):
    """
    Registra un evento de seguridad detectado por el motor en la bitácora
    con su nivel de severidad, método de detección y detalles de origen.
    """
    with lock:
        alertas.appendleft({
            "id": len(alertas) + 1,
            "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hora": hora(),
            "tipo": a.get("tipo", "Sin tipo"),
            "severidad": a.get("severidad", "baja"),
            "metodo": a.get("metodo", ""),
            "src": a.get("src", ""),
            "dst": a.get("dst", ""),
            "puerto": a.get("puerto", ""),
            "descripcion": a.get("descripcion", ""),
            "estado": "Nueva",
        })


def _reloj():
    """
    Monitorea de forma periódica el flujo de paquetes cada segundo
    para construir la serie de tiempo que visualiza la gráfica.
    """
    global _contador_segundo
    while True:
        time.sleep(1)
        with lock:
            serie_pps.append(_contador_segundo)
            _contador_segundo = 0


threading.Thread(target=_reloj, daemon=True).start()

# Motor de captura y detección en red (NIDS)
capturador = sniffer.CapturadorRed(registrar_paquete, registrar_alerta, lambda: configuracion)
al_conectar = capturador.iniciar
al_desconectar = capturador.detener


# Rutas de autenticación y sesión

@app.route("/api/auth/estado")
def api_auth_estado():
    """Consulta si la sesión actual cuenta con privilegios de administrador."""
    usuario = session.get("usuario")
    return jsonify({
        "autenticado": bool(usuario),
        "usuario": usuario or None,
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    """Valida credenciales de acceso administrativo e inicia sesión en el servidor."""
    if not ADMIN_USUARIO or not ADMIN_PASSWORD:
        return jsonify(
            ok=False,
            mensaje="Las credenciales de administrador no están configuradas en el archivo .env."
        ), 500

    datos = request.json or {}
    usuario = str(datos.get("usuario", "")).strip()
    password = str(datos.get("password", "")).strip()

    if usuario == ADMIN_USUARIO and password == ADMIN_PASSWORD:
        session["usuario"] = usuario
        return jsonify(ok=True, usuario=usuario, mensaje="Sesión administrativa iniciada correctamente.")

    return jsonify(ok=False, mensaje="Usuario o contraseña incorrectos."), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Cierra la sesión administrativa activa y elimina los datos de sesión."""
    session.clear()
    return jsonify(ok=True, mensaje="Sesión finalizada.")


# Rutas de la interfaz y servicios API

@app.route("/")
def inicio():
    """Entrega la página principal de la consola de gestión al navegador."""
    return render_template("index.html")


@app.route("/api/hids/puertos")
def api_hids_puertos():
    """
    Consulta y retorna los puertos abiertos en escucha en el host local,
    junto con el proceso y la ruta del ejecutable correspondiente.
    """
    return jsonify(hids.escanear_puertos_locales())


@app.route("/api/interfaces")
def api_interfaces():
    """
    Consulta y lista las tarjetas de red físicas y virtuales del equipo,
    junto con su dirección IP, velocidad y estado de actividad.
    """
    datos = []
    estados = psutil.net_if_stats()
    for nombre, direcciones in psutil.net_if_addrs().items():
        ipv4 = next((d.address for d in direcciones if d.family.name == "AF_INET"), "")
        st = estados.get(nombre)
        datos.append({
            "nombre": nombre,
            "ip": ipv4,
            "activa": bool(st and st.isup),
            "velocidad": st.speed if st else 0,
        })
    datos.sort(key=lambda x: (not x["activa"], x["ip"] == "", x["nombre"]))
    return jsonify(datos)


@app.route("/api/conectar", methods=["POST"])
@requiere_autenticacion
def api_conectar():
    """
    Activa la supervisión en la interfaz de red indicada ejecutando
    la rutina de conexión configurada en el motor.
    """
    interfaz = (request.json or {}).get("interfaz")
    if not interfaz:
        return jsonify(ok=False, mensaje="Selecciona una interfaz de red."), 400
    try:
        al_conectar(interfaz)
    except Exception as e:
        return jsonify(ok=False, mensaje=f"El motor no pudo iniciar: {e}"), 500
    with lock:
        estado.update(conectado=True, interfaz=interfaz, inicio=time.time())
    return jsonify(ok=True, mensaje=f"Conectado a {interfaz}")


@app.route("/api/desconectar", methods=["POST"])
@requiere_autenticacion
def api_desconectar():
    """
    Detiene el proceso de captura en la interfaz activa y actualiza
    el estado general del sistema.
    """
    try:
        al_desconectar()
    finally:
        with lock:
            estado.update(conectado=False)
    return jsonify(ok=True, mensaje="Captura detenida")


@app.route("/api/estado")
def api_estado():
    """
    Devuelve un resumen completo del estado del sistema, volumen de paquetes,
    distribución de protocolos, orígenes frecuentes y alertas recientes.
    """
    with lock:
        sev = collections.Counter(a["severidad"] for a in alertas)
        return jsonify({
            **estado,
            "duracion": int(time.time() - estado["inicio"]) if estado["conectado"] and estado["inicio"] else 0,
            "pps": list(serie_pps),
            "protocolos": dict(protocolos.most_common(8)),
            "origenes": [{"ip": ip, "n": n} for ip, n in origenes.most_common(6)],
            "paquetes_recientes": list(paquetes_recientes)[:40],
            "alertas_recientes": list(alertas)[:20],
            "total_alertas": len(alertas),
            "por_severidad": {"alta": sev["alta"], "media": sev["media"], "baja": sev["baja"]},
        })


@app.route("/api/bitacora")
def api_bitacora():
    """
    Filtra y retorna los registros de alertas almacenados de acuerdo con
    el nivel de severidad y el texto de búsqueda suministrados.
    """
    sev = request.args.get("severidad", "")
    q = request.args.get("q", "").lower()
    with lock:
        filas = [a for a in alertas
                 if (not sev or a["severidad"] == sev)
                 and (not q or q in f'{a["tipo"]} {a["src"]} {a["dst"]} {a["descripcion"]}'.lower())]
    return jsonify(filas)


@app.route("/api/bitacora/<int:id_alerta>", methods=["POST"])
@requiere_autenticacion
def api_marcar(id_alerta):
    """Actualiza el estado de atención de una alerta dentro de la bitácora."""
    nuevo = (request.json or {}).get("estado", "Revisada")
    with lock:
        for a in alertas:
            if a["id"] == id_alerta:
                a["estado"] = nuevo
                return jsonify(ok=True)
    return jsonify(ok=False), 404


@app.route("/api/bitacora.csv")
def api_csv():
    """
    Exporta el contenido completo de la bitácora en formato CSV
    sanitizando cada celda para evitar inyección de fórmulas en hojas de cálculo.
    """
    with lock:
        filas = list(alertas)
    buf = io.StringIO()
    campos = ["id", "fecha", "tipo", "severidad", "metodo", "src", "dst", "puerto", "descripcion", "estado"]
    w = csv.DictWriter(buf, fieldnames=campos, extrasaction="ignore")
    w.writeheader()
    for fila in filas:
        fila_saneada = {k: sanitizar_campo_csv(fila.get(k, "")) for k in campos}
        w.writerow(fila_saneada)
    nombre = f"bitacora_nids_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nombre}"})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    """
    Permite consultar la configuración actual del motor o actualizar
    sus valores previa autenticación y validación estricta de tipos y rangos.
    """
    if request.method == "POST":
        if not session.get("usuario"):
            api_key = request.headers.get("X-API-Key")
            auth_header = request.headers.get("Authorization", "")
            token_bearer = auth_header.split(" ", 1)[1] if auth_header.startswith("Bearer ") else ""
            autorizado_por_token = bool(ADMIN_API_KEY and (api_key == ADMIN_API_KEY or token_bearer == ADMIN_API_KEY))
            if not autorizado_por_token:
                return jsonify(ok=False, mensaje="Autenticación requerida para modificar configuración."), 401

        nuevos = request.json or {}
        errores = []

        # Validación estricta de ventana temporal
        if "ventana_seg" in nuevos:
            try:
                val = int(nuevos["ventana_seg"])
                if 1 <= val <= 300:
                    configuracion["ventana_seg"] = val
                else:
                    errores.append("La ventana de análisis debe estar entre 1 y 300 segundos.")
            except (ValueError, TypeError):
                errores.append("El valor de ventana_seg debe ser numérico.")

        # Validación estricta de umbral de conexiones
        if "umbral_conexiones" in nuevos:
            try:
                val = int(nuevos["umbral_conexiones"])
                if 1 <= val <= 1000:
                    configuracion["umbral_conexiones"] = val
                else:
                    errores.append("El umbral de conexiones debe estar entre 1 y 1000.")
            except (ValueError, TypeError):
                errores.append("El valor de umbral_conexiones debe ser numérico.")

        # Validación estricta de umbral de paquetes por segundo
        if "umbral_pps" in nuevos:
            try:
                val = int(nuevos["umbral_pps"])
                if 1 <= val <= 50000:
                    configuracion["umbral_pps"] = val
                else:
                    errores.append("El umbral de paquetes por segundo debe estar entre 1 y 50000.")
            except (ValueError, TypeError):
                errores.append("El valor de umbral_pps debe ser numérico.")

        # Validación estricta de período de enfriamiento
        if "enfriamiento_seg" in nuevos:
            try:
                val = int(nuevos["enfriamiento_seg"])
                if 1 <= val <= 600:
                    configuracion["enfriamiento_seg"] = val
                else:
                    errores.append("El tiempo de enfriamiento debe estar entre 1 y 600 segundos.")
            except (ValueError, TypeError):
                errores.append("El valor de enfriamiento_seg debe ser numérico.")

        # Validación estricta de severidad mínima
        if "notificar_severidad_minima" in nuevos:
            val = str(nuevos["notificar_severidad_minima"]).strip().lower()
            if val in ("baja", "media", "alta"):
                configuracion["notificar_severidad_minima"] = val
            else:
                errores.append("La severidad mínima debe ser baja, media o alta.")

        # Validación estricta de lista blanca de direcciones IP
        if "lista_blanca" in nuevos:
            ips = [ip.strip() for ip in str(nuevos["lista_blanca"]).split(",") if ip.strip()]
            ips_validas = []
            for ip in ips:
                valida, resultado = firewall.validar_ip(ip)
                if valida:
                    ips_validas.append(resultado)
                else:
                    errores.append(f"Dirección IP no válida en lista blanca: {resultado}")
            if not errores or len(ips_validas) == len(ips):
                configuracion["lista_blanca"] = ", ".join(ips_validas)

        if errores:
            return jsonify(ok=False, mensaje="; ".join(errores)), 400

        return jsonify(ok=True, config=configuracion)

    return jsonify(configuracion)


@app.route("/api/limpiar", methods=["POST"])
@requiere_autenticacion
def api_limpiar():
    """Restablece los acumuladores de paquetes y el historial de tráfico."""
    with lock:
        paquetes_recientes.clear()
        protocolos.clear()
        origenes.clear()
        estado.update(paquetes=0, bytes=0)
    return jsonify(ok=True)


@app.route("/api/firewall/bloquear_puerto", methods=["POST"])
@requiere_autenticacion
def api_firewall_bloquear_puerto():
    """Bloquea un puerto local en el Firewall de Windows registrando la auditoría."""
    datos = request.json or {}
    puerto = datos.get("puerto")
    protocolo = datos.get("protocolo", "TCP")
    usuario, ip_origen = obtener_actor_actual()

    if puerto is None:
        return jsonify(ok=False, mensaje="Se requiere indicar el puerto."), 400

    resultado = firewall.bloquear_puerto(puerto, protocolo, usuario=usuario, ip_origen=ip_origen)
    codigo = 200 if resultado.get("ok") else 400
    return jsonify(resultado), codigo


@app.route("/api/firewall/desbloquear_puerto", methods=["POST"])
@requiere_autenticacion
def api_firewall_desbloquear_puerto():
    """Elimina la regla de bloqueo de un puerto registrando el retiro en auditoría."""
    datos = request.json or {}
    puerto = datos.get("puerto")
    protocolo = datos.get("protocolo", "TCP")
    usuario, ip_origen = obtener_actor_actual()

    if puerto is None:
        return jsonify(ok=False, mensaje="Se requiere indicar el puerto."), 400

    resultado = firewall.desbloquear_puerto(puerto, protocolo, usuario=usuario, ip_origen=ip_origen)
    codigo = 200 if resultado.get("ok") else 400
    return jsonify(resultado), codigo


@app.route("/api/firewall/bloquear_ip", methods=["POST"])
@requiere_autenticacion
def api_firewall_bloquear_ip():
    """Bloquea el tráfico proveniente de una dirección IP atacante con registro de auditoría."""
    datos = request.json or {}
    ip = str(datos.get("ip", "")).strip()
    usuario, ip_origen = obtener_actor_actual()

    if not ip:
        return jsonify(ok=False, mensaje="Se requiere indicar la dirección IP."), 400

    resultado = firewall.bloquear_ip(ip, usuario=usuario, ip_origen=ip_origen)
    codigo = 200 if resultado.get("ok") else 400
    return jsonify(resultado), codigo


@app.route("/api/firewall/desbloquear_ip", methods=["POST"])
@requiere_autenticacion
def api_firewall_desbloquear_ip():
    """Elimina la regla de bloqueo para una dirección IP documentando el retiro en auditoría."""
    datos = request.json or {}
    ip = str(datos.get("ip", "")).strip()
    usuario, ip_origen = obtener_actor_actual()

    if not ip:
        return jsonify(ok=False, mensaje="Se requiere indicar la dirección IP."), 400

    resultado = firewall.desbloquear_ip(ip, usuario=usuario, ip_origen=ip_origen)
    codigo = 200 if resultado.get("ok") else 400
    return jsonify(resultado), codigo


@app.route("/api/firewall/reglas")
def api_firewall_reglas():
    """Retorna las reglas activas generadas por el sistema en el Firewall."""
    return jsonify(firewall.listar_reglas_nids())


@app.route("/api/firewall/auditoria")
def api_firewall_auditoria():
    """Retorna el historial completo de auditoría de bloqueos y retiros del firewall."""
    return jsonify(firewall.obtener_auditoria())


@app.route("/api/simular_ataque", methods=["POST"])
@requiere_autenticacion
def api_simular_ataque():
    """
    Ejecuta una ráfaga controlada de escaneo de puertos de prueba
    validando previamente la dirección IP de origen simulada.
    """
    ip = str((request.get_json(silent=True) or {}).get("ip", "192.168.1.185")).strip()
    valida, res_ip = firewall.validar_ip(ip)
    if not valida:
        return jsonify(ok=False, mensaje=f"Dirección IP no válida para simulación: {res_ip}"), 400

    capturador.simular_ataque_escaneo(res_ip)
    return jsonify(ok=True, mensaje=f"Ráfaga de escaneo simulada desde {res_ip}")


if __name__ == "__main__":
    # Inicio del servidor web local
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
