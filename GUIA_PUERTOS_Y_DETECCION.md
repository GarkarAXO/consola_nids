<!--
  Guía técnica de puertos, protocolos y detección - Consola NIDS
  Autor:
-->

# Guía Técnica: Puertos, Protocolos y Detección de Amenazas

Este documento explica de forma clara y técnica los conceptos fundamentales solicitados para la evaluación del proyecto de detección de intrusos (NIDS/HIDS), detallando cómo el sistema implementa la detección de puertos, rastreo de procesos, filtrado de protocolos y bloqueo de tráfico.

---

## 1. Puertos de Red y sus Rangos de Operación

En redes de computadoras (modelo TCP/IP), un puerto de red es un identificador numérico de 16 bits (rango del **0 al 65535**) que permite al sistema operativo dirigir el tráfico que entra o sale de la tarjeta de red hacia la aplicación o proceso correcto.

La IANA (Internet Assigned Numbers Authority) clasifica la totalidad de los puertos en tres rangos oficiales:

| Rango de Puertos | Denominación Oficial | Propósito y Servicios Representativos |
| :--- | :--- | :--- |
| **0 – 1023** | **Puertos bien conocidos** (*Well-Known*) | Servicios fundamentales del sistema operativo e infraestructura de red. Requieren permisos de administrador para abrirse. Ejemplos: `HTTP (80)`, `HTTPS (443)`, `SSH (22)`, `DNS (53)`, `FTP (21)`, `SMB (445)`. |
| **1024 – 49151** | **Puertos registrados** (*Registered*) | Asignados a aplicaciones de usuario y servicios comerciales. Ejemplos: Servidores de bases de datos como `MySQL (3306)` y `PostgreSQL (5432)`, o aplicaciones web locales como la consola Flask (`5000`). |
| **49152 – 65535** | **Puertos dinámicos o efímeros** (*Private/Dynamic*) | Puertos temporales que el sistema operativo asigna dinámicamente a clientes que originan conexiones salientes (por ejemplo, el puerto origen temporal que usa tu navegador al consultar un sitio web). |

---

## 2. Cómo Detecta el Proyecto los Puertos Abiertos y Rastrea su Ruta

Para responder a la necesidad de saber qué aplicaciones mantienen puertos abiertos en el equipo, el sistema implementa un módulo de Host IDS en `hids.py`:

```
               MECÁNICA DE DETECCIÓN LOCAL (HIDS)
               
┌───────────────────────┐
│ psutil.net_connections│  ---> Consulta sockets en estado LISTEN
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Filtrado por Socket  │  ---> Extrae IP local, Puerto y Protocolo (TCP/UDP)
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Resolución de PID    │  ---> Obtiene el Identificador de Proceso en Windows
└──────────┬────────────┘
           │
           ▼
┌───────────────────────┐
│  Rastreo de Disco     │  ---> Invoca proc.exe() para obtener la ruta absoluta
└───────────────────────┘       (Ejemplo: C:\Windows\System32\svchost.exe)
```

### Proceso paso a paso:
1. **Consulta del estado de red:** Se utiliza la función `psutil.net_connections(kind='inet')` para inspeccionar la tabla de sockets del sistema operativo.
2. **Filtrado de sockets activos:** Se identifican los sockets TCP en estado `LISTEN` y sockets UDP vinculados a direcciones locales.
3. **Asociación con el proceso:** Por cada puerto se recupera el PID (`conn.pid`).
4. **Rastreo de la ruta en disco:** Mediante `proc = psutil.Process(pid)`, se extrae tanto el nombre del archivo ejecutable (`proc.name()`) como su ubicación completa en el disco duro (`proc.exe()`).
5. **Protección de privilegios:** Si el proceso pertenece al núcleo del sistema operativo (como `System` o servicios protegidos), el código captura la excepción `psutil.AccessDenied` para evitar caídas y reportar el proceso de forma segura.

Este resultado se puede consultar directamente en la terminal con `python hids.py` o mediante la ruta API `GET /api/hids/puertos` en la consola web.

---

## 3. Cómo Habilitar o Bloquear Puertos y Direcciones IP (Fase 2: Firewall)

Existe una diferencia técnica importante entre un sistema de detección y uno de prevención:
- **IDS (Intrusion Detection System):** Es un sistema pasivo. Su función es inspeccionar, correlacionar y generar alertas en la bitácora sin alterar el flujo de red.
- **IPS (Intrusion Prevention System) / Firewall:** Es un sistema activo que toma una decisión de respuesta (bloquear el tráfico, cerrar el socket o descartar los paquetes).

En entornos Windows, el módulo `firewall.py` implementa el control activo ejecutando comandos de **Windows Firewall** con `netsh advfirewall`:

### Bloquear un puerto específico:
```powershell
netsh advfirewall firewall add rule name="NIDS_RULE_BLOCK_PORT_4444_TCP" dir=in action=block protocol=TCP localport=4444
```

### Bloquear una dirección IP atacante completa:
```powershell
netsh advfirewall firewall add rule name="NIDS_RULE_BLOCK_IP_192_168_1_150" dir=in action=block remoteip=192.168.1.150
```

### Habilitar nuevamente el puerto o retirar la regla:
```powershell
netsh advfirewall firewall delete rule name="NIDS_RULE_BLOCK_PORT_4444_TCP"
```

### Implementación en el backend (`firewall.py`):
El backend encapsula estos comandos en funciones Python que validan las entradas y capturan las respuestas del sistema operativo:
- `bloquear_puerto(puerto, protocolo)`: Invoca la regla de entrada para el puerto indicado.
- `desbloquear_puerto(puerto, protocolo)`: Elimina la regla por su nombre único.
- `bloquear_ip(ip)`: Impide toda comunicación de entrada proveniente de dicha dirección.
- `listar_reglas_nids()`: Consulta todas las reglas creadas con el prefijo `NIDS_RULE_`.

> [!NOTE]
> Para que las órdenes de bloqueo del Firewall se apliquen de forma efectiva en Windows, la consola de comandos o terminal debe iniciarse con permisos de Administrador (*"Ejecutar como administrador"*). Si no cuenta con dichos privilegios, el sistema captura el aviso y notifica al usuario sin provocar caídas.

---

## 4. Tipos de Protocolos que se Pueden Inspeccionar o Bloquear

El sistema opera analizando diferentes capas del modelo TCP/IP:

### Protocolos de Capa de Transporte (Capa 4)
- **TCP (Transmission Control Protocol):** Protocolo orientado a conexión. Se inspeccionan banderas (*flags*) como SYN, ACK, FIN, RST para detectar escaneos de puertos y conexiones anómalas.
- **UDP (User Datagram Protocol):** Protocolo sin conexión. Se utiliza para monitorear tráfico DNS, transmisiones multimedia o ataques de amplificación.
- **ICMP (Internet Control Message Protocol):** Mensajes de control y diagnóstico. Permite detectar sondeos de presencia de equipos en la red (mensajes *Echo Request / Echo Reply* tipo Ping).

### Protocolos de Capa de Aplicación (Capa 7)
- **DNS (Puerto 53):** Resolución de nombres de dominio. Permite vigilar consultas hacia dominios maliciosos o túneles de exfiltración de datos.
- **HTTP / HTTPS (Puertos 80 y 443):** Tráfico web. Permite evaluar firmas de ataque como inyecciones SQL o accesos a rutas administrativas.
- **SSH / RDP (Puertos 22 y 3389):** Protocolos de administración remota. Se monitorean para identificar ataques de fuerza bruta por intentos reiterados de autenticación.

---

## 5. Cómo Detecta el Sistema un Escaneo de Puertos en la Red

Un atacante habitualmente utiliza herramientas de escaneo (como Nmap) para descubrir qué puertos están abiertos antes de lanzar un ataque específico.

El NIDS detecta este comportamiento mediante **reglas de anomalía y correlación temporal**:

1. **Ventana de tiempo deslizante:** El sistema agrupa los paquetes recibidos en periodos configurables (por ejemplo, 5 segundos).
2. **Agrupación por dirección IP de origen:** Se contabilizan los puertos de destino distintos a los que una misma IP intenta conectarse dentro de esa ventana de tiempo.
3. **Disparo de umbral:** Si una dirección IP contacta a más de 10 puertos distintos en menos de 5 segundos (comportamiento no habitual de un usuario legítimo), el motor genera de inmediato una alerta de severidad alta con método **Anomalía**:
   - `Tipo:` Intento de escaneo de puertos (Port Scan).
   - `Origen:` IP del atacante.
   - `Método:` Anomalía por dispersión de puertos.
   - `Descripción:` Múltiples solicitudes de conexión dirigidas a puertos cerrados o secuenciales.

---

## 6. Flujo de Decisión en la Interfaz Web (Consola de Gestión)

La consola de administración integra la detección y la respuesta en un flujo directo para el operador de seguridad:

1. **Monitoreo en pestaña "Puertos Locales":** El operador consulta la tabla en vivo con los puertos en escucha, sus procesos y la ruta física en disco.
2. **Detección de servicio anómalo:** Si se detecta un proceso no autorizado (ejemplo: un puerto desconocido o un servicio inseguro como Telnet en puerto 23), el operador puede pulsar el botón **"Bloquear"**.
3. **Confirmación y ejecución:** La interfaz envía la solicitud a `/api/firewall/bloquear_puerto`, la cual invoca `netsh` para cerrar el puerto en el firewall del equipo en tiempo real.
4. **Notificación de estado:** El resultado se despliega mediante una notificación emergente en pantalla informando si la regla fue activada exitosamente.

---

## 7. Requisitos de Privilegios y Procedimiento de Prueba Real en Windows

Para ejecutar pruebas reales de inspección de paquetes y mitigación con Firewall, es indispensable iniciar la terminal con privilegios de **Administrador**.

### Justificación técnica de privilegios en Windows
1. **Acceso a sockets en modo promiscuo (`sniffer.py`):**  
   El kernel de Windows restringe la creación de sockets crudos (`socket.SOCK_RAW`) y la activación del modo promiscuo (`SIO_RCVALL`) exclusivamente a cuentas con permisos de Administrador. Si se ejecuta como usuario estándar, Windows rechaza la apertura con el error `WinError 10013` para prevenir la intercepción no autorizada de paquetes ajenos.
2. **Administración activa del Firewall de Windows (`firewall.py`):**  
   La herramienta `netsh advfirewall` requiere elevación para insertar o eliminar reglas en la tabla del sistema. Sin privilegios elevados, el sistema operativo rechaza la orden indicando *"La operación solicitada requiere elevación"*.
3. **Resolución de ejecutables de procesos del sistema (`hids.py`):**  
   Un usuario regular solo puede consultar la ruta de sus propios programas. La ejecución como Administrador permite a `psutil` consultar y resolver la ruta física de los servicios protegidos del sistema (`C:\Windows\System32\svchost.exe`, etc.).

### Procedimiento para iniciar la prueba real
1. Presiona la tecla **Windows**, escribe **PowerShell** o **cmd**.
2. Haz clic derecho y selecciona **"Ejecutar como administrador"**.
3. Navega al directorio del proyecto:
   ```powershell
   cd C:\Users\ERIKC\OneDrive\Desktop\consola_nids\consola_nids
   ```
4. Inicia la aplicación con el intérprete del entorno virtual:
   ```powershell
   .\venv\Scripts\python.exe app.py
   ```
5. Abre en tu navegador web: `http://127.0.0.1:5000`.

### Metodología de demostración en vivo

#### A. Verificación de Tráfico Legítimo
- Selecciona tu tarjeta de red activa (por ejemplo, *Wi-Fi* o *Ethernet*) y pulsa **"Conectar"**.
- Abre cualquier sitio web en tu navegador o ejecuta en otra terminal:
  ```powershell
  ping 8.8.8.8
  ```
- Observa cómo la gráfica de paquetes por segundo (PPS) se eleva de inmediato y la tabla de tráfico registra las consultas DNS, conexiones HTTPS y mensajes ICMP en tiempo real.

#### B. Verificación de Ataque Real con Nmap
- Desde otro equipo dentro del mismo segmento de red local (o desde tu propia máquina apuntando a tu dirección IP):
  ```bash
  nmap -p 20-100 IP_DE_TU_EQUIPO
  ```
- El NIDS interceptará las solicitudes SYN dirigidas a múltiples puertos. Al superar el umbral en la ventana de tiempo, se activará la alerta roja por **Escaneo de Puertos**.
- Al pulsar **"Bloquear IP"** en la tarjeta de alerta, el sistema ejecutará la regla en Windows Firewall y cortará toda comunicación proveniente del atacante.
