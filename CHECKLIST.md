<!--
  Lista de control y áreas por cubrir - Consola NIDS
  Autor:
-->

# Control de Avance y Hoja de Ruta - NIDS ESIME Zacatenco

Este documento centraliza el estado actual del proyecto, los componentes implementados y las áreas pendientes para consolidar el sistema como un IDS híbrido funcional tanto en red como en equipo.

---

## 1. Módulos y Funcionalidades Implementadas

### Capa de Presentación y Frontend
- [x] Separación modular de responsabilidades en archivos independientes (`index.html`, `style.css`, `app.js`).
- [x] Diseño ergonómico en tema claro de baja fatiga visual con paleta guinda institucional y acentos en verde esmeralda (#019f6c).
- [x] Panel de monitorización con indicadores de rendimiento (paquetes totales, volumen de datos, paquetes/s, alertas por severidad y tiempo de actividad).
- [x] Gráfica temporal en Canvas nativo de paquetes por segundo (últimos 60 segundos), libre de dependencias CDN externas.
- [x] Visualización de distribución de protocolos y principales direcciones IP de origen mediante barras porcentuales dinámicas.
- [x] Tabla de inspección de tráfico en vivo con desplazamiento y actualización continua.
- [x] Vista de alertas con clasificación visual por nivel de severidad (alta, media, baja), método de detección, filtrado reactivo por texto y severidad, botón para despejar alertas activas y botón de marcación masiva a "Revisada".
- [x] Vista de bitácora con filtros combinados (severidad, método de detección y búsqueda textual), vaciado permanente administrativo de registros y exportación CSV con filtros activos y protección contra inyección de fórmulas.
- [x] Pestaña de Auditoría de Firewall (IPS Audit Trail) con filtros por acción (Bloqueo/Desbloqueo), estado de regla (Activo/Retirado/Fallido) y búsqueda textual, botón de vaciado administrativo y exportación de bitácora de auditoría a CSV.
- [x] Formulario dinámico para consulta y ajuste de parámetros de detección (ventanas de tiempo, umbrales y listas blancas).
- [x] Logo institucional personalizable directamente desde código (vía CSS o etiqueta HTML).
- [x] Pestaña interactiva de Puertos Locales (Host IDS) con filtrado por protocolo, búsqueda y botón de bloqueo.
- [x] Sanitización de cadenas en cliente contra inyecciones de código en el DOM.

### Capa de Backend y Servicios API
- [x] Servidor web ligero en Flask con rutas API desacopladas (`/api/interfaces`, `/api/conectar`, `/api/desconectar`, `/api/estado`, `/api/bitacora`, `/api/config`, `/api/limpiar`).
- [x] Motor de captura y análisis de paquetes de red en tiempo real (`sniffer.py`).
- [x] Decodificación nativa de cabeceras IPv4, TCP (banderas SYN/ACK/FIN/RST), UDP, ICMP y DNS.
- [x] Motor de detección por anomalía para escaneos de puertos (*Port Scanning*) y ráfagas DoS.
- [x] Detección por firmas para intentos de conexión a puertos críticos (21, 23, 445, 3389, 4444).
- [x] Botón y endpoint `/api/simular_ataque` para demostración controlada de detección en vivo.
- [x] Módulo de mitigación activa y firewall (`firewall.py` con comandos `netsh advfirewall` para bloquear y desbloquear puertos e IPs).
- [x] Endpoints API de control de firewall (`/api/firewall/bloquear_puerto`, `/api/firewall/bloquear_ip`, `/api/firewall/reglas`).
- [x] Enumeración de interfaces de red activas en el sistema operativo mediante `psutil`.
- [x] Estructuras de datos sincronizadas en memoria con `threading.Lock` para control de concurrencia básica.
- [x] Hilo en segundo plano para el cálculo periódico de paquetes por segundo.
- [x] Ganchos (`hooks`) enlazados al capturador para arranque y detención en la interfaz elegida.

### Estándares de Documentación y Mantenimiento
- [x] Definición de la Skill de documentación profesional (`.agents/skills/documentacion-codigo/SKILL.md`).
- [x] Directriz de proyecto permanente (`GEMINI.md`) para garantizar código sin marcas de agua, sin cajas ASCII y con autoría libre.
- [x] Guía técnica sobre puertos, rangos IANA, protocolos y mecanismos de bloqueo de firewall (`GUIA_PUERTOS_Y_DETECCION.md`).
- [x] Módulo HIDS para detección y rastreo de puertos locales en escucha con ruta de ejecutables (`hids.py` y endpoint `/api/hids/puertos`).

---

## 2. Áreas por Cubrir y Próximos Pasos

### Módulo Núcleo de Red (NIDS)
- [x] Motor de captura de paquetes en tiempo real con sockets e inspección de tráfico (`sniffer.py`).
- [x] Análisis y clasificación de protocolos IPv4, TCP, UDP, ICMP y DNS con la librería estándar `struct`.
- [x] Detección de escaneo de puertos por anomalía y conexiones a puertos críticos por firma.
- [ ] Incorporar soporte opcional para filtros BPF avanzados mediante Scapy / Npcap si se requiere inspección de carga útil profunda (Deep Packet Inspection).

### Módulo Núcleo de Equipo (HIDS)
- [x] Monitorear conexiones y puertos en escucha locales con `psutil`, resolviendo nombre de proceso y ruta de disco (`hids.py`).
- [x] Implementar un hilo de telemetría de host para inspeccionar consumo anómalo de recursos en procesos activos (`hids.py` y endpoint `/api/hids/telemetria`).
- [x] Detectar anomalías en el consumo de CPU y memoria asociadas a posibles procesos maliciosos.
- [x] Generar alertas automáticas de host si se abre un puerto sensible (ej. 23, 4444) o un nuevo servicio en escucha e integrarlas en la bitácora.

### Persistencia y Almacenamiento
- [x] Reemplazar las colas volátiles en memoria por una base de datos local embebida (SQLite `nids.db`) en el módulo `db.py` para garantizar que las alertas y la bitácora sobrevivan al reinicio del sistema.
- [x] Crear un archivo de configuración persistente (`config.json`) para que los umbrales modificados por el usuario no se pierdan al reiniciar la aplicación.
- [x] Persistencia de la bitácora de auditoría de firewall en SQLite para documentar formalmente cada acción de mitigación.

### Seguridad y Robustecimiento
- [x] Mitigar vulnerabilidad de inyección de fórmulas CSV anteponiendo un apóstrofe (`'`) a campos que inicien con `=`, `+`, `-` o `@`.
- [x] Implementar validación y tipado estricto en el endpoint `POST /api/config` para evitar errores 500 ante entradas incorrectas.
- [x] Incorporar un mecanismo de autenticación y control de sesiones para restringir el acceso a la consola administrativa (`/api/login`, cookies de sesión y tokens de API).
- [x] Restringir y validar estrictamente los endpoints administrativos (`/api/conectar`, `/api/desconectar`, `/api/limpiar`, `/api/simular_ataque`, endpoints de firewall).
- [x] Validación estricta de direcciones IP con el estándar IPv4 (descartando loopback, multidifusión e inyecciones de comandos) mediante `ipaddress`.
- [x] Validación estricta de puertos (1 a 65535) y protocolos permitidos (TCP / UDP).
- [x] Ejecución segura de llamadas al sistema con `subprocess.run` pasando listas de argumentos y desactivando el intérprete de comandos (`shell=False`).
- [x] Módulo y pestaña web de Auditoría de Firewall (IPS Audit Trail) que documenta solicitante, fecha y hora de aplicación, momento de retiro y estado de cada mitigación.
- [ ] Añadir protección contra peticiones cruzadas no autorizadas (CSRF).
- [ ] Preparar el despliegue con un servidor WSGI de producción para Windows (como Waitress) para evitar limitaciones del servidor de desarrollo Werkzeug.

### Rendimiento y Optimización
- [ ] Sustituir la inserción paquete por paquete bajo bloqueo exclusivo por un búfer o cola interna de procesamiento por lotes para evitar cuello de botella ante ráfagas altas de tráfico.
- [ ] Evaluar el uso de Server-Sent Events (SSE) en lugar del sondeo HTTP periódico de un segundo para reducir la sobrecarga de red en la interfaz de gestión.
