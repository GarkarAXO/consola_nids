"""
Módulo de mitigación activa y firewall - Bloqueo, habilitación y auditoría
Autor:

Este módulo gestiona las reglas de bloqueo y mitigación en el Firewall de
Windows mediante llamadas directas y seguras a netsh. Incluye validación
estricta de direcciones IP, puertos y protocolos, así como un registro de
auditoría que documenta la identidad del solicitante, la fecha y hora de
aplicación y el momento de retiro de cada regla.
"""

import ipaddress
import subprocess
import threading
from datetime import datetime

import db

# Prefijo distintivo para identificar reglas generadas por el sistema NIDS
PREFIJO_REGLA = "NIDS_RULE_"


def validar_ip(ip):
    """
    Valida estrictamente que una dirección corresponda al estándar IPv4
    y que no pertenezca a rangos reservados o peligrosos para bloqueo.
    """
    if not isinstance(ip, str):
        return False, "La dirección IP debe ser una cadena de texto."
    ip_limpia = ip.strip()
    if not ip_limpia:
        return False, "La dirección IP no puede estar vacía."

    try:
        direccion = ipaddress.IPv4Address(ip_limpia)
    except ValueError:
        return False, f"La dirección '{ip_limpia}' no es una dirección IPv4 válida."

    if direccion.is_loopback:
        return False, "No se permite bloquear la dirección de bucle local (127.0.0.0/8)."
    if direccion.is_unspecified:
        return False, "No se permite bloquear la dirección no especificada (0.0.0.0)."
    if direccion.is_multicast:
        return False, "No se permite bloquear direcciones de multidifusión (multicast)."

    return True, str(direccion)


def validar_puerto(puerto):
    """
    Valida estrictamente que el número de puerto sea un entero
    dentro del rango estándar IANA (1 a 65535).
    """
    try:
        num = int(puerto)
        if 1 <= num <= 65535:
            return True, num
        return False, f"El puerto {num} está fuera del rango permitido (1 a 65535)."
    except (ValueError, TypeError):
        return False, "El puerto debe ser un número entero válido."


def validar_protocolo(protocolo):
    """
    Valida que el protocolo indicado pertenezca a la lista autorizada (TCP o UDP).
    """
    if not isinstance(protocolo, str):
        return False, "El protocolo debe ser una cadena de texto."
    proto = protocolo.strip().upper()
    if proto in ("TCP", "UDP"):
        return True, proto
    return False, f"Protocolo no admitido '{proto}'. Se requiere TCP o UDP."


def ejecutar_comando_firewall(argumentos):
    """
    Ejecuta un comando netsh pasando los argumentos como lista parametrizada
    sin utilizar shell=True para eliminar riesgos de inyección de comandos.
    """
    try:
        resultado = subprocess.run(
            argumentos,
            shell=False,
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="replace"
        )
        salida = (resultado.stdout + resultado.stderr).strip()

        if resultado.returncode == 0:
            return {"ok": True, "mensaje": "Operación aplicada en el firewall exitosamente."}
        elif "elevaci" in salida.lower() or "administrator" in salida.lower():
            return {
                "ok": False,
                "mensaje": "Se requieren permisos de Administrador en Windows para modificar reglas de Firewall."
            }
        else:
            return {"ok": False, "mensaje": f"Respuesta del firewall: {salida or 'Error desconocido'}"}
    except Exception as e:
        return {"ok": False, "mensaje": f"Error al invocar comando del firewall: {e}"}


def registrar_auditoria(tipo, objetivo, accion, solicitado_por, ip_origen, resultado, detalle):
    """
    Inserta un nuevo evento en la bitácora de auditoría persistente de mitigación.
    """
    return db.guardar_auditoria(tipo, objetivo, accion, solicitado_por, ip_origen, resultado, detalle)


def marcar_retiro_auditoria(objetivo, retirado_por):
    """
    Actualiza la fecha de retiro en registros de bloqueo previos activos para el mismo objetivo.
    """
    db.marcar_retiro_auditoria(objetivo, retirado_por)


def obtener_auditoria(accion=None, estado=None, texto=None):
    """
    Retorna la lista completa de eventos de auditoría ordenada desde el más reciente
    con soporte para filtrado por acción, estado de regla y búsqueda textual.
    """
    return db.consultar_auditoria(limite=500, accion=accion, estado=estado, texto=texto)


def bloquear_puerto(puerto, protocolo="TCP", usuario="admin", ip_origen="127.0.0.1"):
    """
    Crea una regla de entrada en el Firewall de Windows para bloquear el tráfico
    hacia un puerto local, registrando la solicitud en la bitácora de auditoría.
    """
    valido_pto, res_pto = validar_puerto(puerto)
    if not valido_pto:
        registrar_auditoria("PUERTO", str(puerto), "BLOQUEO", usuario, ip_origen, False, res_pto)
        return {"ok": False, "mensaje": res_pto}

    valido_proto, res_proto = validar_protocolo(protocolo)
    if not valido_proto:
        registrar_auditoria("PUERTO", f"{res_pto}/{protocolo}", "BLOQUEO", usuario, ip_origen, False, res_proto)
        return {"ok": False, "mensaje": res_proto}

    puerto_num = res_pto
    proto_str = res_proto
    objetivo = f"{puerto_num}/{proto_str}"
    nombre_regla = f"{PREFIJO_REGLA}BLOCK_PORT_{puerto_num}_{proto_str}"

    argumentos = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={nombre_regla}",
        "dir=in",
        "action=block",
        f"protocol={proto_str}",
        f"localport={puerto_num}"
    ]

    res = ejecutar_comando_firewall(argumentos)
    registrar_auditoria("PUERTO", objetivo, "BLOQUEO", usuario, ip_origen, res["ok"], res["mensaje"])

    if res["ok"]:
        res["nombre_regla"] = nombre_regla
        res["puerto"] = puerto_num
        res["protocolo"] = proto_str
    return res


def desbloquear_puerto(puerto, protocolo="TCP", usuario="admin", ip_origen="127.0.0.1"):
    """
    Elimina la regla de bloqueo existente para un puerto y protocolo,
    actualizando la bitácora de auditoría con la fecha y responsable del retiro.
    """
    valido_pto, res_pto = validar_puerto(puerto)
    if not valido_pto:
        registrar_auditoria("PUERTO", str(puerto), "DESBLOQUEO", usuario, ip_origen, False, res_pto)
        return {"ok": False, "mensaje": res_pto}

    valido_proto, res_proto = validar_protocolo(protocolo)
    if not valido_proto:
        registrar_auditoria("PUERTO", f"{res_pto}/{protocolo}", "DESBLOQUEO", usuario, ip_origen, False, res_proto)
        return {"ok": False, "mensaje": res_proto}

    puerto_num = res_pto
    proto_str = res_proto
    objetivo = f"{puerto_num}/{proto_str}"
    nombre_regla = f"{PREFIJO_REGLA}BLOCK_PORT_{puerto_num}_{proto_str}"

    argumentos = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={nombre_regla}"
    ]

    res = ejecutar_comando_firewall(argumentos)
    if res["ok"]:
        marcar_retiro_auditoria(objetivo, usuario)

    registrar_auditoria("PUERTO", objetivo, "DESBLOQUEO", usuario, ip_origen, res["ok"], res["mensaje"])
    return res


def bloquear_ip(ip, usuario="admin", ip_origen="127.0.0.1"):
    """
    Crea una regla en el Firewall de Windows para bloquear el tráfico proveniente
    de una dirección IP atacante, documentando la acción en la bitácora de auditoría.
    """
    valida, res_ip = validar_ip(ip)
    if not valida:
        registrar_auditoria("IP", str(ip), "BLOQUEO", usuario, ip_origen, False, res_ip)
        return {"ok": False, "mensaje": res_ip}

    ip_valida = res_ip
    nombre_regla = f"{PREFIJO_REGLA}BLOCK_IP_{ip_valida.replace('.', '_')}"

    argumentos = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={nombre_regla}",
        "dir=in",
        "action=block",
        f"remoteip={ip_valida}"
    ]

    res = ejecutar_comando_firewall(argumentos)
    registrar_auditoria("IP", ip_valida, "BLOQUEO", usuario, ip_origen, res["ok"], res["mensaje"])

    if res["ok"]:
        res["nombre_regla"] = nombre_regla
        res["ip"] = ip_valida
    return res


def desbloquear_ip(ip, usuario="admin", ip_origen="127.0.0.1"):
    """
    Elimina la regla de bloqueo para una dirección IP específica,
    registrando en la auditoría el momento del retiro y el usuario que lo solicitó.
    """
    valida, res_ip = validar_ip(ip)
    if not valida:
        registrar_auditoria("IP", str(ip), "DESBLOQUEO", usuario, ip_origen, False, res_ip)
        return {"ok": False, "mensaje": res_ip}

    ip_valida = res_ip
    nombre_regla = f"{PREFIJO_REGLA}BLOCK_IP_{ip_valida.replace('.', '_')}"

    argumentos = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={nombre_regla}"
    ]

    res = ejecutar_comando_firewall(argumentos)
    if res["ok"]:
        marcar_retiro_auditoria(ip_valida, usuario)

    registrar_auditoria("IP", ip_valida, "DESBLOQUEO", usuario, ip_origen, res["ok"], res["mensaje"])
    return res


def listar_reglas_nids():
    """
    Consulta en el Firewall de Windows todas las reglas de bloqueo activas
    que hayan sido generadas por este sistema.
    """
    argumentos = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    try:
        resultado = subprocess.run(
            argumentos,
            shell=False,
            capture_output=True,
            text=True,
            encoding="cp850",
            errors="replace"
        )
        salida = resultado.stdout
        reglas = []

        bloques = salida.split("\n\n")
        for bloque in bloques:
            if PREFIJO_REGLA in bloque:
                lineas = [l.strip() for l in bloque.splitlines() if l.strip()]
                info = {}
                for linea in lineas:
                    if ":" in linea:
                        clave, valor = linea.split(":", 1)
                        info[clave.strip()] = valor.strip()

                nombre = info.get("Nombre de regla") or info.get("Rule Name", "")
                if nombre.startswith(PREFIJO_REGLA):
                    reglas.append({
                        "nombre": nombre,
                        "accion": info.get("Acción") or info.get("Action", "Bloquear"),
                        "direccion": info.get("Dirección") or info.get("Direction", "Entrada"),
                        "protocolo": info.get("Protocolo") or info.get("Protocol", "Cualquiera"),
                        "puerto_local": info.get("LocalPort") or info.get("Puerto local", "N/A"),
                        "ip_remota": info.get("RemoteIP") or info.get("IP remota", "N/A"),
                    })
        return reglas
    except Exception as e:
        return [{"error": f"Error al listar reglas: {e}"}]
