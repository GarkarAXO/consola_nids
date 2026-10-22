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
- [x] Vista de alertas con clasificación visual por nivel de severidad (alta, media, baja) y método de detección.
- [x] Vista de bitácora con filtros por severidad, búsqueda textual por IP/tipo y función para marcar alertas como revisadas.
- [x] Exportación de registros de bitácora en formato CSV descargable.
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
- [ ] Implementar un hilo de telemetría de host para inspeccionar consumo anómalo de recursos en procesos activos.
- [ ] Detectar anomalías en el consumo de CPU y memoria asociadas a posibles procesos maliciosos.
- [ ] Generar alertas automáticas de host si se abre un puerto sensible (ej. 23, 4444) e integrarlas en la bitácora.

### Persistencia y Almacenamiento
- [ ] Reemplazar las colas volátiles en memoria (`collections.deque`) por una base de datos local embebida (SQLite) para garantizar que las alertas y la bitácora sobrevivan al reinicio del sistema.
- [ ] Crear un archivo de configuración persistente (`config.json` o tabla en base de datos) para que los umbrales modificados por el usuario no se pierdan al reiniciar la aplicación.

### Seguridad y Robustecimiento
- [ ] Mitigar vulnerabilidad de inyección de fórmulas CSV anteponiendo un apóstrofe (`'`) a campos que inicien con `=`, `+`, `-` o `@`.
- [ ] Implementar validación y tipado estricto en el endpoint `POST /api/config` para evitar errores 500 ante entradas incorrectas.
- [ ] Incorporar un mecanismo de autenticación básica o control de sesiones para restringir el acceso a la consola administrativa.
- [ ] Añadir protección contra peticiones cruzadas no autorizadas (CSRF).
- [ ] Preparar el despliegue con un servidor WSGI de producción para Windows (como Waitress) para evitar limitaciones del servidor de desarrollo Werkzeug.

### Rendimiento y Optimización
- [ ] Sustituir la inserción paquete por paquete bajo bloqueo exclusivo por un búfer o cola interna de procesamiento por lotes para evitar cuello de botella ante ráfagas altas de tráfico.
- [ ] Evaluar el uso de Server-Sent Events (SSE) en lugar del sondeo HTTP periódico de un segundo para reducir la sobrecarga de red en la interfaz de gestión.
