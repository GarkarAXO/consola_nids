/*
  Lógica de interfaz - Consola de gestión NIDS
  Autor:
*/

// Selector abreviado de elementos del DOM
const $ = s => document.querySelector(s);

// Sanitización de texto para prevenir inyecciones HTML en el navegador
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
}[c]));

let conectado = false;
let ultimoTotalAlertas = 0;
let sesionAutenticada = false;
let cacheAuditoria = [];

// Descripciones de parámetros para la pestaña de configuración
const AYUDA = {
  ventana_seg: ["Ventana de análisis (s)", "Tiempo de agrupación de tráfico para evaluación de umbrales."],
  umbral_conexiones: ["Umbral de conexiones", "Límite de conexiones simultáneas por IP antes de alertar."],
  umbral_pps: ["Umbral de paquetes/s", "Volumen máximo de paquetes por segundo considerado normal."],
  enfriamiento_seg: ["Enfriamiento (s)", "Intervalo mínimo entre alertas repetidas del mismo origen."],
  lista_blanca: ["Lista blanca", "Direcciones IP excluidas de la generación de alertas."],
  notificar_severidad_minima: ["Severidad mínima a notificar", "Nivel mínimo requerido (baja, media o alta)."],
};

// Despliegue de notificaciones temporales en pantalla
function aviso(texto) {
  const a = $("#aviso");
  if (!a) return;
  a.textContent = texto;
  a.classList.add("ver");
  clearTimeout(a._t);
  a._t = setTimeout(() => a.classList.remove("ver"), 3500);
}

// Conversión de bytes a magnitudes legibles
function bytes(n) {
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < 3) {
    n /= 1024;
    i++;
  }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}

// Conversión de segundos a formato de reloj HH:MM:SS
function reloj(s) {
  return [s / 3600 | 0, (s / 60) % 60 | 0, s % 60]
    .map(x => String(x).padStart(2, "0"))
    .join(":");
}

// Comunicación asíncrona con los endpoints de la API Flask
async function api(url, datos) {
  const opciones = datos === undefined
    ? {}
    : {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(datos)
      };
  try {
    const respuesta = await fetch(url, opciones);
    const json = await respuesta.json();
    if (respuesta.status === 401) {
      actualizarUIAuth(false);
      abrirModalLogin(json.mensaje || "Autenticación administrativa requerida.");
    }
    return json;
  } catch (e) {
    return { ok: false, mensaje: "Error de comunicación con el servidor." };
  }
}

// Gestión de autenticación administrativa y modal de inicio de sesión

function abrirModalLogin(mensajeError) {
  const modal = $("#modalLogin");
  const errBox = $("#msgLoginError");
  if (!modal) return;
  modal.hidden = false;
  if (errBox) {
    if (mensajeError) {
      errBox.textContent = mensajeError;
      errBox.hidden = false;
    } else {
      errBox.hidden = true;
    }
  }
  const txtPass = $("#txtPassword");
  if (txtPass) {
    txtPass.value = "";
    setTimeout(() => txtPass.focus(), 50);
  }
}

function cerrarModalLogin() {
  const modal = $("#modalLogin");
  if (modal) modal.hidden = true;
}

function actualizarUIAuth(autenticado) {
  sesionAutenticada = Boolean(autenticado);
  const btn = $("#btnAuth");
  if (!btn) return;

  if (sesionAutenticada) {
    btn.textContent = "Cerrar Sesión";
    btn.className = "secundario";
  } else {
    btn.textContent = "Iniciar Sesión";
    btn.className = "primario";
  }
}

async function consultarEstadoAuth() {
  const r = await api("/api/auth/estado");
  actualizarUIAuth(r.autenticado);
}

async function iniciarSesion() {
  const usuario = $("#txtUsuario") ? $("#txtUsuario").value.trim() : "";
  const password = $("#txtPassword") ? $("#txtPassword").value.trim() : "";
  const errBox = $("#msgLoginError");

  if (!usuario || !password) {
    if (errBox) {
      errBox.textContent = "Por favor ingresa usuario y contraseña.";
      errBox.hidden = false;
    }
    return;
  }

  const r = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ usuario, password })
  });
  const res = await r.json();

  if (r.ok && res.ok) {
    cerrarModalLogin();
    actualizarUIAuth(true);
    aviso(res.mensaje);
    if ($("#firewall") && $("#firewall").classList.contains("activa")) {
      cargarAuditoriaFirewall();
    }
  } else {
    if (errBox) {
      errBox.textContent = res.mensaje || "Credenciales incorrectas.";
      errBox.hidden = false;
    }
  }
}

async function cerrarSesion() {
  const r = await api("/api/logout", {});
  actualizarUIAuth(false);
  aviso(r.mensaje || "Sesión finalizada.");
}

// Configuración de escuchas para el módulo de autenticación
if ($("#btnAuth")) {
  $("#btnAuth").onclick = () => {
    if (sesionAutenticada) {
      cerrarSesion();
    } else {
      abrirModalLogin();
    }
  };
}

if ($("#btnCancelarLogin")) $("#btnCancelarLogin").onclick = cerrarModalLogin;
if ($("#formLogin")) $("#formLogin").onsubmit = iniciarSesion;

// Alternancia entre vistas desde los botones de navegación
document.querySelectorAll("nav button").forEach(boton => {
  boton.onclick = () => {
    document.querySelectorAll("nav button, .vista").forEach(elem => elem.classList.remove("activa"));
    boton.classList.add("activa");
    $("#" + boton.dataset.vista).classList.add("activa");

    if (boton.dataset.vista === "bitacora") cargarBitacora();
    if (boton.dataset.vista === "puertos") cargarPuertosLocales();
    if (boton.dataset.vista === "firewall") {
      cargarReglasFirewall();
      cargarAuditoriaFirewall();
    }
    if (boton.dataset.vista === "config") cargarConfig();
    if (boton.dataset.vista === "alertas") {
      ultimoTotalAlertas = -1;
      $("#cntAlertas").hidden = true;
    }
  };
});

// Obtención del catálogo de tarjetas de red disponibles
async function cargarInterfaces() {
  const lista = await api("/api/interfaces");
  if (!Array.isArray(lista)) return;
  $("#selInterfaz").innerHTML = lista.map(i =>
    `<option value="${esc(i.nombre)}">${esc(i.nombre)}${i.ip ? " · " + esc(i.ip) : ""}${i.activa ? "" : " (inactiva)"}</option>`
  ).join("") || "<option>No se encontraron interfaces</option>";
}

if ($("#btnRefrescar")) $("#btnRefrescar").onclick = cargarInterfaces;

// Conexión o desconexión del proceso de captura
if ($("#btnConectar")) {
  $("#btnConectar").onclick = async () => {
    const r = conectado
      ? await api("/api/desconectar", {})
      : await api("/api/conectar", { interfaz: $("#selInterfaz").value });
    aviso(r.mensaje);
    actualizar();
  };
}

// Limpieza de métricas de tráfico acumuladas
if ($("#btnLimpiar")) {
  $("#btnLimpiar").onclick = async () => {
    await api("/api/limpiar", {});
    actualizar();
  };
}

// Trazado de la gráfica temporal de paquetes por segundo
function dibujar(serie) {
  const c = $("#grafica");
  if (!c) return;
  const r = window.devicePixelRatio || 1;
  const w = c.clientWidth;
  const h = 200;

  c.width = w * r;
  c.height = h * r;
  const g = c.getContext("2d");
  g.scale(r, r);

  const max = Math.max(10, ...serie) * 1.15;
  const pi = 36, pb = 20;
  const ancho = w - pi - 8;
  const alto = h - pb - 8;

  g.font = "11px Segoe UI";
  g.fillStyle = "#64748b";
  g.strokeStyle = "#e2e8f0";

  for (let i = 0; i <= 4; i++) {
    const y = 8 + (alto * i) / 4;
    g.beginPath();
    g.moveTo(pi, y);
    g.lineTo(w - 8, y);
    g.stroke();
    g.fillText(Math.round(max * (1 - i / 4)), 2, y + 4);
  }

  g.fillText("-60 s", pi, h - 4);
  g.fillText("ahora", w - 40, h - 4);

  const x = i => pi + (ancho * i) / (serie.length - 1);
  const y = v => 8 + alto * (1 - v / max);

  const grad = g.createLinearGradient(0, 8, 0, 8 + alto);
  grad.addColorStop(0, "rgba(122, 28, 61, 0.18)");
  grad.addColorStop(1, "rgba(122, 28, 61, 0.01)");

  g.beginPath();
  serie.forEach((v, i) => (i ? g.lineTo(x(i), y(v)) : g.moveTo(x(i), y(v))));
  g.lineTo(x(serie.length - 1), 8 + alto);
  g.lineTo(pi, 8 + alto);
  g.fillStyle = grad;
  g.fill();

  g.beginPath();
  serie.forEach((v, i) => (i ? g.lineTo(x(i), y(v)) : g.moveTo(x(i), y(v))));
  g.strokeStyle = "#7a1c3d";
  g.lineWidth = 2;
  g.stroke();
}

// Representación en barras porcentuales de protocolos e IPs
function barras(obj, contenedor, mono) {
  const pares = Object.entries(obj);
  const total = pares.reduce((s, [, n]) => s + n, 0);

  $(contenedor).innerHTML = pares.length
    ? pares.map(([k, n]) => {
        const pct = total > 0 ? (n / total * 100).toFixed(1) : "0.0";
        return `<div class="barra">
          <span class="${mono ? "mono" : ""}">${esc(k)}</span>
          <div><i style="width:${pct}%"></i></div>
          <em>${n}</em>
        </div>`;
      }).join("")
    : '<div class="vacio">Sin datos</div>';
}

// Estructura visual para cada registro de alerta
function tarjetaAlerta(a) {
  const botonBloqueo = a.src && a.src !== "127.0.0.1"
    ? `<button class="peligro" style="padding:2px 8px; font-size:11px; margin-top:6px" onclick="accionBloquearIp('${esc(a.src)}')">Bloquear IP</button>`
    : "";

  return `<div class="alerta ${esc(a.severidad)}">
    <div class="tira"></div>
    <div>
      <b>${esc(a.tipo)}</b> <span class="sev ${esc(a.severidad)}">${esc(a.severidad)}</span>
      <p>${esc(a.descripcion)}</p>
      <p class="mono">${esc(a.src)} &rarr; ${esc(a.dst)}${a.puerto ? ":" + esc(a.puerto) : ""} &middot; ${esc(a.metodo)}</p>
      ${botonBloqueo}
    </div>
    <div class="mono" style="color:var(--tenue)">${esc(a.hora)}</div>
  </div>`;
}

// Acción de bloqueo de IP atacante en el Firewall de Windows
async function accionBloquearIp(ip) {
  if (!confirm(`¿Confirmas el bloqueo de la IP atacante ${ip} en el Firewall de Windows?`)) return;
  const r = await api("/api/firewall/bloquear_ip", { ip });
  aviso(r.mensaje);
  if ($("#firewall") && $("#firewall").classList.contains("activa")) {
    cargarReglasFirewall();
    cargarAuditoriaFirewall();
  }
}

// Sondeo regular de métricas, volumen de tráfico y alertas recientes
async function actualizar() {
  let e;
  try {
    e = await api("/api/estado");
    if (!e || e.ok === false) return;
  } catch {
    return;
  }

  conectado = e.conectado;
  $("#pastilla").classList.toggle("on", conectado);
  $("#txtEstado").textContent = conectado ? "Monitoreando " + e.interfaz : "Desconectado";
  $("#btnConectar").textContent = conectado ? "Desconectar" : "Conectar";
  $("#btnConectar").className = conectado ? "peligro" : "exito";
  $("#selInterfaz").disabled = conectado;

  $("#kPaq").textContent = (e.paquetes || 0).toLocaleString("es-MX");
  $("#kBytes").textContent = bytes(e.bytes || 0);
  $("#kPps").textContent = e.pps && e.pps.length ? e.pps[e.pps.length - 1] : 0;
  $("#kAlta").textContent = e.por_severidad ? e.por_severidad.alta : 0;
  $("#kMedBaja").textContent = e.por_severidad ? `${e.por_severidad.media} / ${e.por_severidad.baja}` : "0 / 0";
  $("#kTiempo").textContent = reloj(e.duracion || 0);

  if (e.pps) dibujar(e.pps);
  if (e.protocolos) barras(e.protocolos, "#protocolos");
  if (e.origenes) barras(Object.fromEntries(e.origenes.map(o => [o.ip, o.n])), "#origenes", true);

  $("#tbTrafico").innerHTML = (e.paquetes_recientes && e.paquetes_recientes.length)
    ? e.paquetes_recientes.map(p =>
        `<tr>
          <td class="mono">${esc(p.hora)}</td>
          <td class="mono">${esc(p.src)}</td>
          <td class="mono">${esc(p.dst)}</td>
          <td>${esc(p.proto)}</td>
          <td class="mono">${esc(p.puerto)}</td>
          <td>${esc(p.len)}</td>
          <td>${esc(p.info)}</td>
        </tr>`
      ).join("")
    : `<tr><td colspan="7" class="vacio">${conectado ? "Esperando paquetes del motor…" : "Conecta una interfaz para ver el tráfico"}</td></tr>`;

  $("#listaAlertas").innerHTML = (e.alertas_recientes && e.alertas_recientes.length)
    ? e.alertas_recientes.map(tarjetaAlerta).join("")
    : '<div class="vacio">No hay alertas. Cuando el motor detecte algo aparecerá aquí.</div>';

  if (ultimoTotalAlertas === -1) ultimoTotalAlertas = e.total_alertas;
  const nuevas = (e.total_alertas || 0) - ultimoTotalAlertas;
  if (nuevas > 0 && !$("#alertas").classList.contains("activa")) {
    $("#cntAlertas").hidden = false;
    $("#cntAlertas").textContent = nuevas;
  }
  if ($("#alertas").classList.contains("activa")) {
    ultimoTotalAlertas = e.total_alertas;
  }
}

// Consulta de bitácora con filtros por severidad o término de búsqueda
async function cargarBitacora() {
  const q = new URLSearchParams({ severidad: $("#fSev").value, q: $("#fTexto").value });
  const filas = await api("/api/bitacora?" + q);
  if (!Array.isArray(filas)) return;
  $("#tbBitacora").innerHTML = filas.length
    ? filas.map(a =>
        `<tr>
          <td>${a.id}</td>
          <td class="mono">${esc(a.fecha)}</td>
          <td><span class="sev ${esc(a.severidad)}">${esc(a.severidad)}</span></td>
          <td>${esc(a.tipo)}</td>
          <td>${esc(a.metodo)}</td>
          <td class="mono">${esc(a.src)}</td>
          <td class="mono">${esc(a.dst)}</td>
          <td class="mono">${esc(a.puerto)}</td>
          <td>${esc(a.descripcion)}</td>
          <td>${a.estado === "Nueva"
            ? `<button onclick="marcar(${a.id})">Marcar revisada</button>`
            : esc(a.estado)}</td>
        </tr>`
      ).join("")
    : '<tr><td colspan="10" class="vacio">Sin registros</td></tr>';
}

// Cambio de estado de una alerta a revisada
async function marcar(id) {
  await api("/api/bitacora/" + id, { estado: "Revisada" });
  cargarBitacora();
}

if ($("#btnBuscar")) $("#btnBuscar").onclick = cargarBitacora;
if ($("#fTexto")) {
  $("#fTexto").onkeydown = e => {
    if (e.key === "Enter") cargarBitacora();
  };
}

// Consulta de puertos locales y procesos asociados (Host IDS)
let cachePuertosLocales = [];

async function cargarPuertosLocales() {
  $("#tbPuertos").innerHTML = '<tr><td colspan="8" class="vacio">Consultando puertos en el equipo...</td></tr>';
  try {
    cachePuertosLocales = await api("/api/hids/puertos");
    renderizarTablaPuertos();
  } catch {
    $("#tbPuertos").innerHTML = '<tr><td colspan="8" class="vacio">Error al consultar puertos locales.</td></tr>';
  }
}

function renderizarTablaPuertos() {
  const fProto = $("#fProtoPuerto") ? $("#fProtoPuerto").value : "";
  const fTexto = $("#fTextoPuerto") ? $("#fTextoPuerto").value.toLowerCase().trim() : "";

  const filtrados = (cachePuertosLocales || []).filter(p => {
    const coincideProto = !fProto || p.protocolo === fProto;
    const textoCompleto = `${p.puerto} ${p.proceso} ${p.servicio} ${p.descripcion} ${p.ruta_ejecutable}`.toLowerCase();
    const coincideTexto = !fTexto || textoCompleto.includes(fTexto);
    return coincideProto && coincideTexto;
  });

  $("#tbPuertos").innerHTML = filtrados.length
    ? filtrados.map(p => `
        <tr>
          <td><span class="sev ${p.protocolo === "TCP" ? "media" : "baja"}">${esc(p.protocolo)}</span></td>
          <td class="mono"><b>${p.puerto}</b></td>
          <td><small>${esc(p.rango)}</small></td>
          <td class="mono">${esc(p.proceso)}</td>
          <td class="mono">${p.pid || "-"}</td>
          <td><b>${esc(p.servicio)}</b><br><small style="color:var(--tenue)">${esc(p.descripcion)}</small></td>
          <td class="mono" title="${esc(p.ruta_ejecutable)}" style="max-width:280px; overflow:hidden; text-overflow:ellipsis;">
            ${esc(p.ruta_ejecutable)}
          </td>
          <td>
            <button class="peligro" style="padding:4px 8px; font-size:11px" onclick="accionBloquearPuerto(${p.puerto}, '${esc(p.protocolo)}')">Bloquear</button>
          </td>
        </tr>
      `).join("")
    : '<tr><td colspan="8" class="vacio">No se encontraron puertos con los criterios indicados.</td></tr>';
}

async function accionBloquearPuerto(puerto, protocolo) {
  if (!confirm(`¿Confirmas el bloqueo del puerto ${puerto} (${protocolo}) en el Firewall?`)) return;
  const r = await api("/api/firewall/bloquear_puerto", { puerto, protocolo });
  aviso(r.mensaje);
  if ($("#firewall") && $("#firewall").classList.contains("activa")) {
    cargarReglasFirewall();
    cargarAuditoriaFirewall();
  }
}

if ($("#btnRefrescarPuertos")) $("#btnRefrescarPuertos").onclick = cargarPuertosLocales;
if ($("#fProtoPuerto")) $("#fProtoPuerto").onchange = renderizarTablaPuertos;
if ($("#fTextoPuerto")) $("#fTextoPuerto").oninput = renderizarTablaPuertos;

// Demostración de ataque simulado para verificación de reglas
if ($("#btnProbarDeteccion")) {
  $("#btnProbarDeteccion").onclick = async () => {
    aviso("Ejecutando escaneo de prueba desde 192.168.1.185...");
    const r = await api("/api/simular_ataque", { ip: "192.168.1.185" });
    aviso(r.mensaje);
    actualizar();
  };
}

// Gestión de reglas de mitigación en Firewall y bitácora de auditoría

async function cargarReglasFirewall() {
  const tb = $("#tbReglasFirewall");
  if (!tb) return;
  tb.innerHTML = '<tr><td colspan="7" class="vacio">Consultando reglas del Firewall de Windows...</td></tr>';

  const reglas = await api("/api/firewall/reglas");
  if (!Array.isArray(reglas)) {
    tb.innerHTML = '<tr><td colspan="7" class="vacio">Error al consultar las reglas del firewall.</td></tr>';
    return;
  }

  if (reglas.length === 0) {
    tb.innerHTML = '<tr><td colspan="7" class="vacio">No existen reglas activas creadas por el sistema NIDS.</td></tr>';
    return;
  }

  tb.innerHTML = reglas.map(r => {
    if (r.error) {
      return `<tr><td colspan="7" class="vacio">${esc(r.error)}</td></tr>`;
    }
    const esReglaPuerto = r.nombre.includes("BLOCK_PORT_");
    const esReglaIp = r.nombre.includes("BLOCK_IP_");
    let botonRetiro = "";

    if (esReglaPuerto) {
      const partes = r.nombre.replace("NIDS_RULE_BLOCK_PORT_", "").split("_");
      const pto = partes[0];
      const proto = partes[1] || "TCP";
      botonRetiro = `<button class="peligro" style="padding:3px 8px; font-size:11px" onclick="accionDesbloquearPuertoDirecto(${pto}, '${esc(proto)}')">Retirar Regla</button>`;
    } else if (esReglaIp) {
      const ip = r.nombre.replace("NIDS_RULE_BLOCK_IP_", "").replace(/_/g, ".");
      botonRetiro = `<button class="peligro" style="padding:3px 8px; font-size:11px" onclick="accionDesbloquearIpDirecto('${esc(ip)}')">Retirar Regla</button>`;
    }

    return `<tr>
      <td class="mono"><b>${esc(r.nombre)}</b></td>
      <td><span class="sev alta">${esc(r.accion)}</span></td>
      <td>${esc(r.direccion)}</td>
      <td><span class="sev ${r.protocolo === "TCP" ? "media" : "baja"}">${esc(r.protocolo)}</span></td>
      <td class="mono">${esc(r.puerto_local)}</td>
      <td class="mono">${esc(r.ip_remota)}</td>
      <td>${botonRetiro}</td>
    </tr>`;
  }).join("");
}

async function accionDesbloquearPuertoDirecto(puerto, protocolo) {
  if (!confirm(`¿Confirmas el retiro del bloqueo para el puerto ${puerto} (${protocolo})?`)) return;
  const r = await api("/api/firewall/desbloquear_puerto", { puerto, protocolo });
  aviso(r.mensaje);
  cargarReglasFirewall();
  cargarAuditoriaFirewall();
}

async function accionDesbloquearIpDirecto(ip) {
  if (!confirm(`¿Confirmas el retiro del bloqueo para la dirección IP ${ip}?`)) return;
  const r = await api("/api/firewall/desbloquear_ip", { ip });
  aviso(r.mensaje);
  cargarReglasFirewall();
  cargarAuditoriaFirewall();
}

async function cargarAuditoriaFirewall() {
  const tb = $("#tbAuditoria");
  if (!tb) return;
  try {
    cacheAuditoria = await api("/api/firewall/auditoria");
    renderizarTablaAuditoria();
  } catch {
    tb.innerHTML = '<tr><td colspan="11" class="vacio">Error al obtener registros de auditoría.</td></tr>';
  }
}

function renderizarTablaAuditoria() {
  const tb = $("#tbAuditoria");
  if (!tb) return;
  const fAccion = $("#fAccionAuditoria") ? $("#fAccionAuditoria").value : "";
  const fTexto = $("#fTextoAuditoria") ? $("#fTextoAuditoria").value.toLowerCase().trim() : "";

  const filtrados = (cacheAuditoria || []).filter(item => {
    const coincideAccion = !fAccion || item.accion === fAccion;
    const cadena = `${item.objetivo} ${item.solicitado_por} ${item.retirado_por || ""} ${item.detalle} ${item.estado}`.toLowerCase();
    const coincideTexto = !fTexto || cadena.includes(fTexto);
    return coincideAccion && coincideTexto;
  });

  if (!filtrados.length) {
    tb.innerHTML = '<tr><td colspan="11" class="vacio">No hay eventos en la bitácora de auditoría con los criterios seleccionados.</td></tr>';
    return;
  }

  tb.innerHTML = filtrados.map(ev => {
    const claseAccion = ev.accion === "BLOQUEO" ? "badge-bloqueo" : "badge-desbloqueo";
    const claseEstado = ev.estado === "ACTIVO"
      ? "badge-activo"
      : (ev.estado === "RETIRADO" ? "badge-retirado" : "badge-fallido");

    return `<tr>
      <td class="mono">${ev.id}</td>
      <td><span class="badge-accion ${claseAccion}">${esc(ev.accion)}</span></td>
      <td>${esc(ev.tipo)}</td>
      <td class="mono"><b>${esc(ev.objetivo)}</b></td>
      <td><b>${esc(ev.solicitado_por)}</b></td>
      <td class="mono">${esc(ev.ip_origen)}</td>
      <td class="mono">${esc(ev.fecha_aplicacion || "-")}</td>
      <td class="mono">${esc(ev.fecha_retiro || "-")}</td>
      <td>${esc(ev.retirado_por || "-")}</td>
      <td><span class="badge-estado ${claseEstado}">${esc(ev.estado)}</span></td>
      <td style="max-width:250px; overflow:hidden; text-overflow:ellipsis;" title="${esc(ev.detalle)}">${esc(ev.detalle)}</td>
    </tr>`;
  }).join("");
}

if ($("#btnRefrescarReglas")) $("#btnRefrescarReglas").onclick = cargarReglasFirewall;
if ($("#btnRefrescarAuditoria")) $("#btnRefrescarAuditoria").onclick = cargarAuditoriaFirewall;
if ($("#fAccionAuditoria")) $("#fAccionAuditoria").onchange = renderizarTablaAuditoria;
if ($("#fTextoAuditoria")) $("#fTextoAuditoria").oninput = renderizarTablaAuditoria;

// Generación dinámica del formulario de parámetros
async function cargarConfig() {
  const c = await api("/api/config");
  if (!c || c.ok === false) return;
  $("#formConfig").innerHTML = Object.entries(c).map(([k, v]) => {
    const [titulo, ayuda] = AYUDA[k] || [k, ""];
    const control = k === "notificar_severidad_minima"
      ? `<select id="c_${k}" data-k="${k}">${["baja", "media", "alta"].map(o => `<option ${o === v ? "selected" : ""}>${o}</option>`).join("")}</select>`
      : `<input id="c_${k}" data-k="${k}" type="${typeof v === "number" ? "number" : "text"}" value="${esc(v)}">`;
    return `<div class="campo"><label for="c_${k}">${esc(titulo)}</label>${control}<small>${esc(ayuda)}</small></div>`;
  }).join("");
}

// Envío de la configuración actualizada al servidor
if ($("#btnGuardar")) {
  $("#btnGuardar").onclick = async () => {
    const datos = {};
    document.querySelectorAll("#formConfig [data-k]").forEach(i => {
      datos[i.dataset.k] = i.type === "number" ? Number(i.value) : i.value;
    });
    const r = await api("/api/config", datos);
    aviso(r.ok ? "Configuración guardada" : (r.mensaje || "No se pudo guardar"));
  };
}

// Enlace de redimensionamiento e inicialización general
window.onresize = () => actualizar();

consultarEstadoAuth();
cargarInterfaces();
actualizar();
setInterval(actualizar, 1000);
