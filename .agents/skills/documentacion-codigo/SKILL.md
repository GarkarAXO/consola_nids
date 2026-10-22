---
name: documentacion-codigo
description: >-
  Estándar obligatorio de documentación y comentarios para todos los archivos del proyecto
  (Python, HTML, CSS, JavaScript, etc.). Usar siempre que se redacte, refactorice o documente
  código para mantener un estilo profesional senior, sin emojis ni separadores ASCII decorativos.
---

# Guía y Estándar de Documentación de Código

Este estándar define las reglas obligatorias de comentarios y documentación en todo el repositorio. El objetivo es mantener un código limpio, profesional y accesible tanto para desarrolladores senior como para usuarios generales.

---

## 1. Encabezado Obligatorio por Archivo

Todo archivo de código debe iniciar con un encabezado descriptivo que indique el tipo de archivo, su propósito general y el campo de autor.

### Reglas del encabezado:
- **Autor siempre libre:** Se debe escribir `Autor:` dejando la línea vacía inmediatamente después. Nunca firmar como IA, ni escribir el nombre del asistente, ni incluir leyendas como *"escribe aquí tu nombre"*.
- **Claridad sin tecnicismos excesivos:** La descripción debe ser comprensible y directa, explicando la función del archivo para que cualquier persona o desarrollador senior lo entienda de inmediato.

### Plantillas por lenguaje:

#### Python
```python
"""
Servidor web y API backend - Consola de gestión NIDS
Autor:

Descripción concisa de qué trata el archivo y qué componentes coordina,
redactada en lenguaje natural y comprensible.
"""
```

#### HTML
```html
<!--
  Plantilla HTML - Consola de gestión NIDS
  Autor:
-->
```

#### CSS
```css
/*
  Estilos CSS - Consola de gestión NIDS
  Autor:
*/
```

#### JavaScript
```javascript
/*
  Lógica de interfaz - Consola de gestión NIDS
  Autor:
*/
```

---

## 2. Prohibición de Separadores y Cajas ASCII

Queda estrictamente prohibido el uso de bloques decorativos, cajas y líneas de separación como:

```
==================================================
===== SECCIÓN DE CÓDIGO =====
==================================================
--------------------------------------------------
/************************************************/
```

### Formato correcto:
Utilizar comentarios simples, directos y limpios de una sola línea:
```css
/* Variables de tema y paleta institucional */
```
```javascript
// Sanitización de texto para prevenir inyecciones HTML en el navegador
```
```python
# Estado operativo y métricas en memoria
```

---

## 3. Tono y Redacción de Comentarios

1. **Lenguaje natural humano:** Redacción técnica limpia y declarativa en tiempo presente.
2. **Cero emojis:** Ningún emoji está permitido en comentarios, docstrings ni texto del código.
3. **Sin tono de tutorial o condescendiente:**
   - **Prohibido:** *"Esto te servirá para calcular el porcentaje..."*, *"Aquí puedes colocar tu lógica..."*, *"Esta función te permite conectar la red..."*.
   - **Correcto:** *"Cálculo porcentual de la distribución de tráfico"*, *"Conexión o desconexión del proceso de captura"*.
4. **Brevedad:** Describir con exactitud y síntesis lo que hace el bloque o la función sin redundancias.

---

## 4. Documentación de Funciones y Rutas

- Toda función, método o endpoint debe contar con una breve descripción de su cometido.
- En Python se emplean docstrings limpios:
  ```python
  def registrar_alerta(a):
      """
      Registra un evento de seguridad detectado por el motor en la bitácora
      con su nivel de severidad, método de detección y detalles de origen.
      """
  ```
- En JavaScript se emplean comentarios descriptivos precediendo la función:
  ```javascript
  // Trazado de la gráfica temporal de paquetes por segundo
  function dibujar(serie) { ... }
  ```

---

## 5. Integridad y Limpieza del Código

- El código no debe incluir marcas de agua, etiquetas de generación artificial, firmas ocultas ni caracteres de ancho cero (*zero-width spaces*).
- Las modificaciones deben preservar la estructura y apegarse estrictamente a los patrones establecidos en este estándar.
