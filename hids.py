"""
Módulo de inspección de host (HIDS) - Análisis de puertos locales y procesos
Autor:

Este módulo inspecciona los puertos de red que se encuentran abiertos y en escucha
en la máquina local. Identifica qué aplicación o proceso del sistema operativo
abrió cada puerto, obtiene la ruta completa del archivo ejecutable en el disco y
clasifica el puerto según los rangos establecidos por la IANA.
"""

import socket
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
        # Se examinan sockets en escucha (TCP LISTEN) o sockets UDP enlazados
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

    # Ordenar por número de puerto para facilitar la lectura
    resultados.sort(key=lambda x: x["puerto"])
    return resultados


def imprimir_resumen_terminal():
    """Muestra en la consola de comandos la lista de puertos detectados en el host."""
    puertos = escanear_puertos_locales()
    print(f"Total de puertos locales en escucha detectados: {len(puertos)}\n")
    print(f"{'PROTO':<6} {'PUERTO':<7} {'RANGO':<25} {'PROCESO':<22} {'RUTA DEL EJECUTABLE'}")
    print("-" * 105)
    for p in puertos:
        if "error" in p:
            print(p["error"])
            continue
        ruta_corta = p['ruta_ejecutable']
        if len(ruta_corta) > 42:
            ruta_corta = "..." + ruta_corta[-39:]
        print(f"{p['protocolo']:<6} {p['puerto']:<7} {p['rango']:<25} {p['proceso']:<22} {ruta_corta}")


if __name__ == "__main__":
    imprimir_resumen_terminal()
