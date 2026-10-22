"""
Módulo de mitigación activa y firewall - Bloqueo y habilitación de puertos e IPs
Autor:

Este módulo proporciona funciones para gestionar reglas de bloqueo y apertura
en el Firewall de Windows mediante la herramienta del sistema netsh. Permite al
sistema NIDS/HIDS actuar como un sistema de prevención de intrusos (IPS),
bloqueando puertos vulnerables o direcciones IP identificadas como atacantes.
"""

import subprocess
import re

# Prefijo distintivo para identificar fácilmente las reglas creadas por el NIDS
PREFIJO_REGLA = "NIDS_RULE_"


def ejecutar_comando_firewall(comando):
    """
    Ejecuta un comando netsh en el sistema y retorna el resultado indicando
    si se aplicó con éxito o si requiere permisos de Administrador.
    """
    try:
        resultado = subprocess.run(
            comando,
            shell=True,
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


def bloquear_puerto(puerto, protocolo="TCP"):
    """
    Crea una regla de entrada en el Firewall de Windows para bloquear el tráfico
    dirigido a un puerto local específico.
    """
    protocolo = protocolo.upper()
    if protocolo not in ("TCP", "UDP"):
        return {"ok": False, "mensaje": "El protocolo debe ser TCP o UDP."}

    nombre_regla = f"{PREFIJO_REGLA}BLOCK_PORT_{puerto}_{protocolo}"
    comando = (
        f'netsh advfirewall firewall add rule name="{nombre_regla}" '
        f'dir=in action=block protocol={protocolo} localport={puerto}'
    )
    res = ejecutar_comando_firewall(comando)
    if res["ok"]:
        res["nombre_regla"] = nombre_regla
        res["puerto"] = puerto
        res["protocolo"] = protocolo
    return res


def desbloquear_puerto(puerto, protocolo="TCP"):
    """
    Elimina la regla de bloqueo existente para el puerto y protocolo especificados,
    restaurando el acceso normal.
    """
    protocolo = protocolo.upper()
    nombre_regla = f"{PREFIJO_REGLA}BLOCK_PORT_{puerto}_{protocolo}"
    comando = f'netsh advfirewall firewall delete rule name="{nombre_regla}"'
    return ejecutar_comando_firewall(comando)


def bloquear_ip(ip):
    """
    Crea una regla en el Firewall de Windows para bloquear todo el tráfico
    proveniente de una dirección IP atacante.
    """
    # Validación básica de dirección IPv4
    patron_ip = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(patron_ip, ip):
        return {"ok": False, "mensaje": "Formato de dirección IP inválido."}

    nombre_regla = f"{PREFIJO_REGLA}BLOCK_IP_{ip.replace('.', '_')}"
    comando = (
        f'netsh advfirewall firewall add rule name="{nombre_regla}" '
        f'dir=in action=block remoteip={ip}'
    )
    res = ejecutar_comando_firewall(comando)
    if res["ok"]:
        res["nombre_regla"] = nombre_regla
        res["ip"] = ip
    return res


def desbloquear_ip(ip):
    """Elimina la regla de bloqueo para una dirección IP específica."""
    nombre_regla = f"{PREFIJO_REGLA}BLOCK_IP_{ip.replace('.', '_')}"
    comando = f'netsh advfirewall firewall delete rule name="{nombre_regla}"'
    return ejecutar_comando_firewall(comando)


def listar_reglas_nids():
    """
    Consulta en el Firewall de Windows todas las reglas de bloqueo activas
    que hayan sido generadas por este sistema.
    """
    comando = f'netsh advfirewall firewall show rule name=all'
    try:
        resultado = subprocess.run(
            comando,
            shell=True,
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
                        "puerto_local": info.get("LocalPort", "N/A"),
                        "ip_remota": info.get("RemoteIP", "N/A"),
                    })
        return reglas
    except Exception as e:
        return [{"error": f"Error al listar reglas: {e}"}]
