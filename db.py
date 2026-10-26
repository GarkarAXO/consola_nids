"""
Módulo de persistencia y base de datos local - Consola NIDS / HIDS
Autor:

Este módulo gestiona el almacenamiento permanente de las alertas de seguridad,
los registros de auditoría del firewall y los parámetros de configuración
mediante una base de datos local embebida en SQLite y un archivo de configuración
JSON. Garantiza que las evidencias y decisiones de mitigación se conserven tras
reinicios del sistema operativo o del servidor.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime

# Rutas de almacenamiento local
RUTA_BD = os.environ.get("NIDS_DB_PATH", "nids.db")
RUTA_CONFIG = os.environ.get("NIDS_CONFIG_PATH", "config.json")

_lock_bd = threading.Lock()


def obtener_conexion():
    """
    Establece una conexión con la base de datos local SQLite
    configurada con mapeo asociativo de columnas.
    """
    conn = sqlite3.connect(RUTA_BD, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def inicializar_bd():
    """
    Crea las tablas necesarias en la base de datos local si aún no existen.
    """
    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()

        # Tabla de alertas de seguridad (NIDS y HIDS)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alertas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TEXT NOT NULL,
                hora TEXT NOT NULL,
                tipo TEXT NOT NULL,
                severidad TEXT NOT NULL,
                metodo TEXT NOT NULL,
                src TEXT,
                dst TEXT,
                puerto INTEGER,
                descripcion TEXT,
                estado TEXT NOT NULL DEFAULT 'Nueva'
            )
        """)

        # Tabla de auditoría para mitigación de firewall
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auditoria_firewall (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tipo TEXT NOT NULL,
                objetivo TEXT NOT NULL,
                accion TEXT NOT NULL,
                solicitado_por TEXT NOT NULL,
                ip_origen TEXT NOT NULL,
                fecha_aplicacion TEXT,
                fecha_retiro TEXT,
                retirado_por TEXT,
                estado TEXT NOT NULL,
                detalle TEXT
            )
        """)

        # Índices para acelerar búsquedas y filtros
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alertas_severidad ON alertas(severidad)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alertas_fecha ON alertas(fecha)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_auditoria_objetivo ON auditoria_firewall(objetivo)")

        conn.commit()


# Operaciones de persistencia para Alertas

def guardar_alerta(alerta):
    """
    Inserta un nuevo registro de alerta en la base de datos y retorna su identificador numérico.
    """
    fecha_actual = alerta.get("fecha") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hora_actual = alerta.get("hora") or datetime.now().strftime("%H:%M:%S")

    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alertas (fecha, hora, tipo, severidad, metodo, src, dst, puerto, descripcion, estado)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fecha_actual,
            hora_actual,
            alerta.get("tipo", "Sin tipo"),
            alerta.get("severidad", "baja"),
            alerta.get("metodo", ""),
            alerta.get("src", ""),
            alerta.get("dst", ""),
            int(alerta.get("puerto", 0) or 0),
            alerta.get("descripcion", ""),
            alerta.get("estado", "Nueva")
        ))
        conn.commit()
        return cursor.lastrowid


def actualizar_estado_alerta(id_alerta, nuevo_estado):
    """
    Actualiza el estado de atención de una alerta (ej. Nueva o Revisada).
    """
    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alertas SET estado = ? WHERE id = ?", (nuevo_estado, id_alerta))
        conn.commit()
        return cursor.rowcount > 0


def consultar_alertas(limite=5000, severidad=None, texto=None, metodo=None):
    """
    Consulta registros históricos de alertas aplicando filtros opcionales de severidad, método y texto.
    """
    sql = "SELECT * FROM alertas WHERE 1=1"
    params = []

    if severidad:
        sql += " AND severidad = ?"
        params.append(severidad)

    if metodo:
        sql += " AND LOWER(metodo) LIKE ?"
        params.append(f"%{metodo.lower().strip()}%")

    if texto:
        sql += " AND (LOWER(tipo) LIKE ? OR LOWER(src) LIKE ? OR LOWER(dst) LIKE ? OR LOWER(descripcion) LIKE ?)"
        patron = f"%{texto.lower().strip()}%"
        params.extend([patron, patron, patron, patron])

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limite)

    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        filas = cursor.fetchall()
        return [dict(f) for f in filas]


def limpiar_todas_alertas():
    """
    Elimina todos los registros de alertas almacenados en la base de datos local.
    """
    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alertas")
        try:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'alertas'")
        except Exception:
            pass
        conn.commit()
        return True


def marcar_todas_alertas_revisadas():
    """
    Actualiza el estado de todas las alertas pendientes a Revisada.
    """
    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alertas SET estado = 'Revisada' WHERE estado = 'Nueva'")
        conn.commit()
        return cursor.rowcount


# Operaciones de persistencia para Auditoría de Firewall

def guardar_auditoria(tipo, objetivo, accion, solicitado_por, ip_origen, resultado, detalle):
    """
    Registra una acción de mitigación en la bitácora de auditoría de la base de datos.
    """
    ahora_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    estado = "ACTIVO" if (resultado and accion == "BLOQUEO") else ("RETIRADO" if accion == "DESBLOQUEO" else "FALLIDO")
    fecha_aplicacion = ahora_str if resultado else None

    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO auditoria_firewall (tipo, objetivo, accion, solicitado_por, ip_origen, fecha_aplicacion, fecha_retiro, retirado_por, estado, detalle)
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
        """, (
            tipo,
            objetivo,
            accion,
            solicitado_por or "admin",
            ip_origen or "127.0.0.1",
            fecha_aplicacion,
            estado,
            detalle
        ))
        conn.commit()
        nuevo_id = cursor.lastrowid
        return {
            "id": nuevo_id,
            "tipo": tipo,
            "objetivo": objetivo,
            "accion": accion,
            "solicitado_por": solicitado_por or "admin",
            "ip_origen": ip_origen or "127.0.0.1",
            "fecha_aplicacion": fecha_aplicacion,
            "fecha_retiro": None,
            "retirado_por": None,
            "estado": estado,
            "detalle": detalle,
        }


def marcar_retiro_auditoria(objetivo, retirado_por):
    """
    Actualiza la fecha y usuario de retiro en registros previos de bloqueo activos.
    """
    ahora_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE auditoria_firewall
            SET fecha_retiro = ?, retirado_por = ?, estado = 'RETIRADO'
            WHERE objetivo = ? AND accion = 'BLOQUEO' AND estado = 'ACTIVO'
        """, (ahora_str, retirado_por or "admin", objetivo))
        conn.commit()


def consultar_auditoria(limite=500, accion=None, estado=None, texto=None):
    """
    Retorna la lista de eventos de auditoría ordenada desde el más reciente
    con soporte para filtrado por acción, estado de regla y búsqueda textual.
    """
    sql = "SELECT * FROM auditoria_firewall WHERE 1=1"
    params = []

    if accion:
        sql += " AND accion = ?"
        params.append(accion)

    if estado:
        sql += " AND estado = ?"
        params.append(estado)

    if texto:
        sql += " AND (LOWER(objetivo) LIKE ? OR LOWER(solicitado_por) LIKE ? OR LOWER(retirado_por) LIKE ? OR LOWER(detalle) LIKE ?)"
        patron = f"%{texto.lower().strip()}%"
        params.extend([patron, patron, patron, patron])

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limite)

    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        filas = cursor.fetchall()
        return [dict(f) for f in filas]


def limpiar_toda_auditoria():
    """
    Elimina todos los eventos almacenados en el registro de auditoría de mitigación.
    """
    with _lock_bd, obtener_conexion() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM auditoria_firewall")
        try:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'auditoria_firewall'")
        except Exception:
            pass
        conn.commit()
        return True


# Persistencia de Parámetros de Configuración en JSON

def cargar_configuracion(valores_predeterminados):
    """
    Lee los parámetros del motor de detección desde el archivo config.json local.
    Si el archivo no existe, lo genera con los valores predeterminados suministrados.
    """
    if not os.path.exists(RUTA_CONFIG):
        guardar_configuracion(valores_predeterminados)
        return dict(valores_predeterminados)

    try:
        with open(RUTA_CONFIG, "r", encoding="utf-8") as f:
            datos = json.load(f)
            config_final = dict(valores_predeterminados)
            config_final.update(datos)
            return config_final
    except Exception:
        return dict(valores_predeterminados)


def guardar_configuracion(config):
    """
    Guarda los parámetros de configuración actualizados en config.json.
    """
    try:
        with open(RUTA_CONFIG, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False
