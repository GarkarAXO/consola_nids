<!--
  Guía de inicio y arquitectura - Consola NIDS
  Autor:
-->

# Consola de Gestión NIDS / HIDS - ESIME Zacatenco

Sistema híbrido de detección de intrusos en red y equipo desarrollado para la supervisión y protección del tráfico informático. Cuenta con interfaz gráfica web, capturador de paquetes en tiempo real, motor de detección por firmas y anomalías, analizador de puertos locales con resolución de ejecutables y mitigación activa mediante el Firewall de Windows.

---

## 1. Requisitos e Instalación en Windows

1. Contar con Python 3.10 o superior (marcar la casilla *"Add Python to PATH"* durante la instalación).
2. Abrir una terminal en el directorio del proyecto e instalar las dependencias:
   ```powershell
   pip install flask psutil python-dotenv
   ```
3. Iniciar la consola de gestión:
   ```powershell
   python app.py
   ```
   *(O utilizando el entorno virtual del proyecto: `.\venv\Scripts\python.exe app.py`)*.
4. Abrir en el navegador: `http://127.0.0.1:5000`.

> [!IMPORTANT]
> **Modo Administrador para Pruebas Reales:**  
> Para capturar tráfico físico en modo promiscuo de Windows (`socket.SOCK_RAW`) y aplicar reglas de bloqueo con el Firewall (`netsh`), la terminal (PowerShell o CMD) debe abrirse con la opción **"Ejecutar como administrador"**.

---

## 2. Pestañas de la Interfaz Web

| Pestaña | Funcionalidad |
| :--- | :--- |
| **Monitor** | Métricas en tiempo real (paquetes totales, bytes, duración), gráfica temporal de paquetes/segundo (PPS), barras de protocolos e IPs más activas, y tabla de inspección de tráfico en vivo. |
| **Alertas** | Tarjetas clasificadas por nivel de severidad (alta, media, baja) con filtrado instantáneo por severidad y texto, botón directo para bloquear la IP atacante en el Firewall, botón de marcación masiva a "Revisada" y opción para despejar alertas activas en pantalla. |
| **Bitácora** | Historial filtrable por severidad, método de detección y búsqueda textual, opción para marcar alertas individuales como revisadas, botón para vaciar la bitácora permanentemente y exportación de evidencias a formato CSV respetando los filtros activos. |
| **Puertos Locales** | Módulo Host IDS (HIDS) que lista todos los puertos en escucha en el equipo, clasifica su rango IANA, identifica el proceso y muestra la ruta exacta del ejecutable en disco, con opción de bloqueo directo. |
| **Firewall y Auditoría** | Inspección y revocación directa de reglas activas en Windows Firewall, junto con la bitácora de auditoría (IPS Audit Trail) filtrable por acción, estado de regla y búsqueda textual, botón de vaciado de auditoría y exportación a CSV. |
| **Configuración** | Ajuste dinámico de parámetros de detección (ventana de análisis en segundos, umbrales de conexiones por host, límite de paquetes/s, tiempo de enfriamiento y lista blanca de IPs) con validación estricta de rangos. |

---

## 3. Autenticación y Credenciales Administrativas

Dado que el proceso requiere ejecutarse con privilegios elevados de Administrador en Windows para la captura promiscua y la configuración de `netsh`, todos los endpoints que modifican el estado del sistema o las reglas del cortafuegos están estrictamente protegidos:

- **Usuario predeterminado:** `admin`
- **Contraseña predeterminada:** `admin123`
- **Token de API para scripts o integraciones:** `nids-admin-token-seguro` (vía encabezado `X-API-Key` o `Authorization: Bearer <token>`).
- Las credenciales pueden personalizarse mediante variables de entorno del sistema (`NIDS_ADMIN_USER`, `NIDS_ADMIN_PASSWORD`, `NIDS_API_KEY` y `NIDS_SECRET_KEY`).

---

## 4. Módulos del Sistema

- **`app.py`:** Servidor web Flask y API REST desacoplada que coordina la interfaz con los motores de seguridad, gestiona la autenticación administrativa y sirve la telemetría en vivo.
- **`db.py`:** Motor de persistencia local en SQLite (`nids.db`) y configuración en JSON (`config.json`), asegurando la supervivencia de alertas, auditorías y umbrales ante reinicios.
- **`sniffer.py`:** Motor NIDS de captura y decodificación de protocolos IPv4, TCP (banderas SYN/ACK/FIN/RST), UDP, ICMP, DNS y mDNS, con reglas de detección de escaneos y ráfagas DoS.
- **`hids.py`:** Módulo HIDS que inspecciona las tablas de sockets locales, resuelve procesos, vigila proactivamente la apertura de puertos sensibles y mide la telemetría de recursos (CPU, RAM, disco).
- **`firewall.py`:** Módulo IPS que gestiona reglas de entrada en el Firewall de Windows mediante `netsh advfirewall` (con `shell=False`) e interactúa con el registro de auditoría.
- **`GUIA_PUERTOS_Y_DETECCION.md`:** Documento técnico detallado que explica la teoría de rangos IANA, protocolos y la justificación de privilegios para la defensa ante el asesor.

---

## 5. Procedimiento de Demostración en Vivo

1. **Monitoreo en Vivo:**  
   Iniciar la consola como Administrador, seleccionar la interfaz de red activa (Wi-Fi o Ethernet) y pulsar **"Conectar"**. El tráfico de navegación y consultas DNS comenzará a registrarse inmediatamente.
2. **Prueba Rápida de Detección:**  
   Pulsar el botón **"Probar Detección"** en el encabezado. El sistema generará un escaneo de puertos de prueba desde la IP `192.168.1.185`, disparando una alerta roja por anomalía en la pestaña *Alertas*.
3. **Mitigación Activa:**  
   Pulsar **"Bloquear IP"** en la tarjeta de alerta o **"Bloquear"** sobre cualquier puerto en la pestaña *Puertos Locales* para verificar la creación de la regla en el Firewall de Windows.
