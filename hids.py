"""
Módulo de inspección de host (HIDS) - Análisis de puertos locales, procesos y telemetría
Autor:

Este módulo inspecciona los puertos de red en escucha en la máquina local, identifica
el proceso responsable junto con la ruta de su ejecutable en disco, y provee un hilo
de supervisión proactiva para alertar de inmediato cuando se abre un puerto sensible
o se detecta un consumo anómalo de recursos en el equipo.
"""

import socket
import threading
import time
from datetime import datetime

import psutil

# Clasificación del rango de un puerto según los estándares de la IANA
def clasificar_rango_puerto(puerto):
    """
    Determina si un puerto pertenece al rango de puertos bien conocidos,
    registrados o dinámicos según su número.
    """
    if 0 <= puerto <= 1023:
        return "Bien conocido (0-1023)"
    elif 1024 <= puerto <= 49151:
        return "Registrado (1024-49151)"
    elif 49152 <= puerto <= 65535:
        return "Dinámico o Privado (49152-65535)"
    return "Fuera de rango"


# Catálogo de servicios comunes y niveles de atención
SERVICIOS_COMUNES = {
    21: {"servicio": "FTP", "descripcion": "Transferencia de archivos sin cifrado"},
    22: {"servicio": "SSH", "descripcion": "Acceso remoto seguro"},
    23: {"servicio": "Telnet", "descripcion": "Acceso remoto inseguro en texto plano"},
    25: {"servicio": "SMTP", "descripcion": "Servidor de correo electrónico"},
    53: {"servicio": "DNS", "descripcion": "Resolución de nombres de dominio"},
    80: {"servicio": "HTTP", "descripcion": "Servidor web sin cifrado"},
    443: {"servicio": "HTTPS", "descripcion": "Servidor web seguro con TLS"},
    445: {"servicio": "SMB", "descripcion": "Recursos compartidos de Windows"},
    3306: {"servicio": "MySQL", "descripcion": "Base de datos relacional"},
    3389: {"servicio": "RDP", "descripcion": "Escritorio remoto de Windows"},
    4444: {"servicio": "Metasploit", "descripcion": "Puerto frecuentemente usado por payloads maliciosos"},
    5000: {"servicio": "Flask / Consola NIDS", "descripcion": "Servidor web de la consola de gestión"},
    8080: {"servicio": "HTTP Alternativo", "descripcion": "Servidor web secundario o proxy"},
}


def evaluar_servicio(puerto):
    """
    Identifica si el puerto corresponde a un servicio de red común o
    requiere atención por ser un vector de ataque conocido.
    """
    if puerto in SERVICIOS_COMUNES:
        return SERVICIOS_COMUNES[puerto]
    return {"servicio": "Desconocido / Personalizado", "descripcion": "Servicio de aplicación local"}


def escanear_puertos_locales():
    """
    Examina las conexiones de red activas en el equipo local, filtrando
    aquellas en estado LISTEN para identificar el proceso y la ruta del ejecutable.
    """
    resultados = []
    puertos_vistos = set()

    try:
        conexiones = psutil.net_connections(kind="inet")
    except Exception as e:
        return [{"error": f"No se pudieron consultar las conexiones: {e}"}]

    for conn in conexiones:
        es_listen_tcp = conn.status == psutil.CONN_LISTEN
        es_udp = conn.type == socket.SOCK_DGRAM

        if not (es_listen_tcp or es_udp):
            continue

        ip_local = conn.laddr.ip if conn.laddr else ""
        puerto = conn.laddr.port if conn.laddr else 0
        protocolo = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        clave_unica = (protocolo, ip_local, puerto)
        if clave_unica in puertos_vistos:
            continue
        puertos_vistos.add(clave_unica)

        pid = conn.pid
        nombre_proceso = "Desconocido"
        ruta_ejecutable = "No disponible"

        if pid:
            try:
                proc = psutil.Process(pid)
                nombre_proceso = proc.name()
                ruta_ejecutable = proc.exe() or "Ruta no reportada"
            except psutil.AccessDenied:
                nombre_proceso = "Proceso del sistema"
                ruta_ejecutable = "Acceso restringido por el sistema operativo"
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                nombre_proceso = "Proceso finalizado"
                ruta_ejecutable = "No disponible"
            except Exception:
                nombre_proceso = "Error al consultar proceso"
                ruta_ejecutable = "No disponible"
        else:
            nombre_proceso = "Núcleo del Sistema (Kernel)"
            ruta_ejecutable = "Sistema operativo"

        info_servicio = evaluar_servicio(puerto)

        resultados.append({
            "protocolo": protocolo,
            "ip": ip_local,
            "puerto": puerto,
            "rango": clasificar_rango_puerto(puerto),
            "pid": pid or 0,
            "proceso": nombre_proceso,
            "ruta_ejecutable": ruta_ejecutable,
            "servicio": info_servicio["servicio"],
            "descripcion": info_servicio["descripcion"],
            "sensible": puerto in (21, 23, 445, 3389, 4444),
        })

    resultados.sort(key=lambda x: x["puerto"])
    return resultados


def obtener_telemetria_sistema():
    """
    Recopila métricas operativas de rendimiento del host local (CPU, Memoria RAM,
    espacio en disco y procesos principales con mayor consumo).
    """
    try:
        cpu_total = psutil.cpu_percent(interval=None)
        memoria = psutil.virtual_memory()
        disco = psutil.disk_usage("C:\\" if psutil.WINDOWS else "/")

        top_procesos = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                top_procesos.append({
                    "pid": p.info["pid"],
                    "nombre": p.info["name"] or "Desconocido",
                    "cpu": round(p.info["cpu_percent"] or 0.0, 1),
                    "memoria": round(p.info["memory_percent"] or 0.0, 1),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        top_procesos.sort(key=lambda x: (x["cpu"], x["memoria"]), reverse=True)

        return {
            "ok": True,
            "cpu_porcentaje": cpu_total,
            "cpu_nucleos": psutil.cpu_count(logical=True),
            "memoria_porcentaje": memoria.percent,
            "memoria_usada_mb": round(memoria.used / (1024 * 1024), 1),
            "memoria_total_mb": round(memoria.total / (1024 * 1024), 1),
            "disco_porcentaje": disco.percent,
            "disco_libre_gb": round(disco.free / (1024 * 1024 * 1024), 1),
            "procesos_totales": len(top_procesos),
            "top_procesos": top_procesos[:5],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


class MonitorProactivoHIDS(threading.Thread):
    """
    Hilo de supervisión continua del host que detecta la apertura de nuevos sockets
    locales y emite alertas automáticas ante puertos sensibles o sospechosos.
    """

    def __init__(self, callback_alerta, intervalo_segundos=4.0):
        super().__init__(daemon=True)
        self.callback_alerta = callback_alerta
        self.intervalo = intervalo_segundos
        self.activo = False
        self.puertos_registrados = set()
        self.primer_escaneo = True
        self.ultimo_aviso_cpu = 0

    def run(self):
        """Bucle continuo de verificación de sockets locales y telemetría."""
        self.activo = True
        while self.activo:
            try:
                self._verificar_sockets()
                self._verificar_telemetria()
            except Exception:
                pass
            time.sleep(self.intervalo)

    def _verificar_sockets(self):
        """Compara los sockets actuales contra el catálogo de sockets conocidos."""
        lista_actual = escanear_puertos_locales()
        puertos_actuales = set()

        for item in lista_actual:
            if "error" in item:
                continue

            clave = (item["protocolo"], item["puerto"])
            puertos_actuales.add(clave)

            # Si es el primer escaneo al arrancar, se crea la línea base inicial
            if self.primer_escaneo:
                continue

            # Si se detecta un puerto nuevo que no estaba en la línea base
            if clave not in self.puertos_registrados:
                es_critico = item.get("sensible", False)
                tipo_alerta = "Puerto Crítico Abierto en Host" if es_critico else "Nuevo Puerto en Escucha en Host"
                severidad = "alta" if es_critico else "media"

                self.callback_alerta({
                    "tipo": tipo_alerta,
                    "severidad": severidad,
                    "metodo": "Host IDS (HIDS)",
                    "src": "127.0.0.1",
                    "dst": item["ip"] or "0.0.0.0",
                    "puerto": item["puerto"],
                    "descripcion": (
                        f"El proceso '{item['proceso']}' (PID: {item['pid']}) abrió el puerto "
                        f"{item['puerto']}/{item['protocolo']} ({item['servicio']}). "
                        f"Ruta: {item['ruta_ejecutable']}"
                    ),
                })

        self.puertos_registrados = puertos_actuales
        self.primer_escaneo = False

    def _verificar_telemetria(self):
        """Inspecciona si el host experimenta una sobrecarga anómala de procesamiento."""
        ahora = time.time()
        if ahora - self.ultimo_aviso_cpu < 60.0:
            return

        uso_cpu = psutil.cpu_percent(interval=None)
        if uso_cpu >= 95.0:
            self.ultimo_aviso_cpu = ahora
            self.callback_alerta({
                "tipo": "Consumo Anómalo de CPU en Host",
                "severidad": "media",
                "metodo": "Host IDS (HIDS)",
                "src": "127.0.0.1",
                "dst": "Localhost",
                "puerto": 0,
                "descripcion": f"Carga de procesamiento global elevada al {uso_cpu}% en el equipo local.",
            })

    def detener(self):
        """Detiene el hilo de supervisión del host."""
        self.activo = False
