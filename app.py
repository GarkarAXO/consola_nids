"""
Servidor web y API backend - Consola de gestión NIDS
Autor:

Este archivo coordina el funcionamiento de la consola de gestión para el sistema
de detección de intrusos. Se encarga de recibir los datos de tráfico y las alertas
que genera el motor de seguridad, mantener las estadísticas actualizadas en tiempo
real y proveer los servicios necesarios para que el usuario pueda supervisar la
red, consultar la bitácora y ajustar parámetros desde el navegador.
"""

import collections
import csv
import io
import threading
import time
from datetime import datetime

import psutil
from flask import Flask, Response, jsonify, render_template, request

import firewall
import hids
import sniffer

app = Flask(__name__)
app.json.sort_keys = False
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
    "ventana_seg": 5,
    "umbral_conexiones": 20,
    "umbral_pps": 500,
    "enfriamiento_seg": 30,
    "lista_blanca": "192.168.1.1",
    "notificar_severidad_minima": "baja",
}


def hora():
    """Retorna la hora actual del sistema en formato HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")


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
    para su descarga y posterior revisión.
    """
    with lock:
        filas = list(alertas)
    buf = io.StringIO()
    campos = ["id", "fecha", "tipo", "severidad", "metodo", "src", "dst", "puerto", "descripcion", "estado"]
    w = csv.DictWriter(buf, fieldnames=campos, extrasaction="ignore")
    w.writeheader()
    w.writerows(filas)
    nombre = f"bitacora_nids_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nombre}"})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    """
    Permite consultar la configuración actual del motor o actualizar
    sus valores a través de solicitudes POST.
    """
    if request.method == "POST":
        nuevos = request.json or {}
        with lock:
            for k, v in nuevos.items():
                if k in configuracion:
                    configuracion[k] = type(configuracion[k])(v)
        return jsonify(ok=True, config=configuracion)
    return jsonify(configuracion)


@app.route("/api/limpiar", methods=["POST"])
def api_limpiar():
    """Restablece los acumuladores de paquetes y el historial de tráfico."""
    with lock:
        paquetes_recientes.clear()
        protocolos.clear()
        origenes.clear()
        estado.update(paquetes=0, bytes=0)
    return jsonify(ok=True)


@app.route("/api/firewall/bloquear_puerto", methods=["POST"])
def api_firewall_bloquear_puerto():
    """Bloquea un puerto local en el Firewall de Windows."""
    datos = request.json or {}
    puerto = datos.get("puerto")
    protocolo = datos.get("protocolo", "TCP")
    if not puerto:
        return jsonify(ok=False, mensaje="Se requiere indicar el puerto."), 400
    try:
        resultado = firewall.bloquear_puerto(int(puerto), protocolo)
        return jsonify(resultado)
    except ValueError:
        return jsonify(ok=False, mensaje="El puerto debe ser un valor numérico."), 400


@app.route("/api/firewall/desbloquear_puerto", methods=["POST"])
def api_firewall_desbloquear_puerto():
    """Elimina la regla de bloqueo de un puerto en el Firewall."""
    datos = request.json or {}
    puerto = datos.get("puerto")
    protocolo = datos.get("protocolo", "TCP")
    if not puerto:
        return jsonify(ok=False, mensaje="Se requiere indicar el puerto."), 400
    try:
        resultado = firewall.desbloquear_puerto(int(puerto), protocolo)
        return jsonify(resultado)
    except ValueError:
        return jsonify(ok=False, mensaje="El puerto debe ser un valor numérico."), 400


@app.route("/api/firewall/bloquear_ip", methods=["POST"])
def api_firewall_bloquear_ip():
    """Bloquea el tráfico proveniente de una dirección IP atacante."""
    datos = request.json or {}
    ip = datos.get("ip", "").strip()
    if not ip:
        return jsonify(ok=False, mensaje="Se requiere indicar la dirección IP."), 400
    resultado = firewall.bloquear_ip(ip)
    return jsonify(resultado)


@app.route("/api/firewall/desbloquear_ip", methods=["POST"])
def api_firewall_desbloquear_ip():
    """Elimina la regla de bloqueo para una dirección IP."""
    datos = request.json or {}
    ip = datos.get("ip", "").strip()
    if not ip:
        return jsonify(ok=False, mensaje="Se requiere indicar la dirección IP."), 400
    resultado = firewall.desbloquear_ip(ip)
    return jsonify(resultado)


@app.route("/api/firewall/reglas")
def api_firewall_reglas():
    """Retorna las reglas activas generadas por el sistema en el Firewall."""
    return jsonify(firewall.listar_reglas_nids())


@app.route("/api/simular_ataque", methods=["POST"])
def api_simular_ataque():
    """
    Ejecuta una ráfaga controlada de escaneo de puertos de prueba
    para demostrar en vivo la detección del sistema NIDS.
    """
    ip = (request.get_json(silent=True) or {}).get("ip", "192.168.1.185")
    capturador.simular_ataque_escaneo(ip)
    return jsonify(ok=True, mensaje=f"Ráfaga de escaneo simulada desde {ip}")


if __name__ == "__main__":
    # Inicio del servidor web local
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
