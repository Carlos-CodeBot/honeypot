# Informe ejecutivo de seguridad - versión 2

Actualización basada en el commit `235aa874538c2c044b89d733ad64fa3ab194365a`
de `Carlos-CodeBot/honeypot`. El endpoint y el botón de descarga ya existen
en esa base; esta versión mejora el contenido y la presentación.

## Contenido del informe

1. Resumen para dirección: detecciones, proporción de ataques, IP únicas,
   severidad alta/crítica y comparación con el período anterior. Acciones
   sugeridas con responsables y plazo, sujetas a validación del equipo.
2. Top 10 de IP registradas: cantidad, porcentaje del total de ataques y barras.
3. Top 10 de países: suma de eventos por país, con cobertura de geolocalización,
   registros sin país y registros identificados como red interna.
4. Top 10 de categorías: cantidad, participación y media de confianza almacenada.
5. Un ejemplo real del período por categoría: ID, fecha original, IP, método,
   ruta y query string, extracto de cuerpo o User-Agent, origen y puntuación
   del evento. Se elige el evento más reciente; a igual fecha, mayor ID.
6. Confianza separada entre modelo MLP, reglas y origen no identificado, con
   cobertura, media, mínimo, máximo y distribución por bandas.
7. Evolución diaria, metodología, limitaciones, severidades y rutas objetivo.

Diseño A4 vectorial con encabezados azul oscuro, acentos turquesa, tipografía
Helvetica, indicadores destacados, tablas alternadas, barras y páginas numeradas.
La evidencia se pagina por su altura real. El número de páginas depende de las
categorías y la longitud de las muestras. El PDF de demostración muestra datos
sintéticos e IP de documentación; **no describe actividad real del servidor**.

## Interpretación y denominadores

- Ataque: fila de `attack_logs` con `is_attack=1`. No implica compromiso exitoso.
- Volumen: número de filas, no incidentes únicos, atacantes o sesiones. No hay deduplicación.
- Porcentaje de los rankings: cantidad / total de ataques del período. Los top 10
  no necesariamente suman 100%. Empates: etiqueta ascendente.
- La tabla de IP conserva exactamente la IP registrada, incluida una posible
  cadena `X-Forwarded-For`; no normaliza o certifica el origen. Revise la confianza
  de sus proxies en la instalación antes de atribuir o bloquear.
- País: unión exacta de `attack_logs.ip` con `ip_geo_cache.ip`, sobre **todas**
  las detecciones del período, no solo las IP del top 10. La generación no hace
  consultas de red ni actualiza la caché. País vacío/desconocido y red interna
  quedan fuera del ranking; permanecen en el denominador y se muestran aparte.
- Si no existe la caché, la cobertura es cero y los países no se inventan.
  La caché refleja la información disponible al generar el informe, no una
  geolocalización histórica. Proxies, VPN y caché incompleta limitan la atribución.
- Períodos de 1 a 90 días, ambos extremos inclusivos en UTC; por defecto 30 días.
  El período anterior tiene la misma duración. Fechas sin zona se interpretan
  como UTC; fechas inválidas se excluyen. El día actual puede estar incompleto.
- Sin ataques en la base anterior, la variación porcentual es «No calculable».
  Cero eventos no demuestra que el sensor estuviera operativo.

## Qué significa la confianza de la IA

El motor del commit base combina reglas y un modelo MLP. Primero busca reglas;
si no coincide ninguna, consulta al modelo. No corresponde atribuir a la IA la
confianza de todas las detecciones.

| Origen | Identificación en `notes` | Significado de `confidence` |
| --- | --- | --- |
| Modelo IA (MLP) | exactamente `mlp_model` | Puntuación de la clase elegida, redondeada a dos decimales por el motor |
| Reglas | empieza por `rules=` | Puntuación predefinida de la regla que coincidió |
| No identificado | cualquier otra marca o ausencia | Se muestra por separado; no se presume que proceda del modelo |

Las marcas son evidencia del origen declarado en el registro, no una certificación
independiente. La confianza no equivale a precisión medida, probabilidad calibrada
de compromiso o riesgo empresarial. Para obtener precisión/recall se necesita un
conjunto representativo etiquetado independientemente, con medición de falsos
positivos y falsos negativos.

Las medias usan solo valores numéricos entre 0 y 1, incluidos los extremos.
Nulos, texto y valores fuera de rango se excluyen y se cuentan como no válidos.
Un cero almacenado se conserva como cero: el esquema no permite distinguir un
cero real de un valor histórico por defecto. Sin valores válidos se muestra N/D.
Las bandas son descriptivas y no cambian los umbrales del motor:

| Banda | Rango |
| --- | --- |
| Muy alta | >= 90% |
| Alta | >= 75% y < 90% |
| Media | >= 60% y < 75% |
| Baja | < 60% |

La confianza por categoría combina puntuaciones válidas de ambos mecanismos;
la sección de confianza los separa. La puntuación del ejemplo corresponde solo
a ese evento. «Muestras con puntuación» indica cobertura de toda la categoría.

## Evidencia y datos sensibles

Los ejemplos se extraen de registros del período sin reclasificarlos. Se muestran
como texto literal; el PDF no contiene JavaScript, formularios ni enlaces activos
creados a partir de las peticiones. Se omiten cabeceras completas y se limitan
las longitudes. Una regla pudo activarse por datos fuera del extracto; use el ID
para consultar el registro completo cuando necesite validar la detección.

Se ocultan valores de claves comunes como password, token, secret, api_key,
authorization y cookie mediante un filtro básico de texto. **No es anonimización
completa**: valores codificados, claves no reconocidas, rutas y otros datos pueden
seguir siendo sensibles. Comparta el PDF solo con sus destinatarios autorizados.
Los caracteres no representables en Windows-1252 aparecen como `?`.

## Generar un informe sin reiniciar el servicio

El módulo de producción usa únicamente la biblioteca estándar de Python. No
requiere ReportLab, Poppler, APIs externas ni cambios de esquema o dependencias.
Sobre una copia consistente de SQLite:

```sh
python app/executive_report.py --db /ruta/copia-consistente.db --start 2026-08-01 --end 2026-08-31 --output informe.pdf
```

Para probar en el contenedor existente, desde el repositorio actualizado o desde
el paquete de actualización descomprimido:

```sh
docker cp app/executive_report.py honeypot-web:/tmp/executive_report_v2.py
docker exec honeypot-web sh -c 'python /tmp/executive_report_v2.py --db "${DB_PATH:-/data/honeypot.db}" --start 2026-08-01 --end 2026-08-31 --output /tmp/informe-ejecutivo.pdf'
docker cp honeypot-web:/tmp/informe-ejecutivo.pdf ./informe-ejecutivo.pdf
```

Adapte fechas y nombre del contenedor. Esta opción no actualiza el botón del
proceso web ni conserva el módulo temporal al recrear el contenedor. El informe
lee la base en modo `ro` y `query_only`, dentro de una transacción coherente, y
cierra la conexión antes del renderizado. No modifica datos ni entrena el modelo.

Consultas adicionales de rankings y muestras pueden recorrer la tabla varias
veces. Se conserva el límite de aproximadamente dos segundos para consultas y
200 ms para esperar bloqueos. En bases grandes puede ser necesario usar una
copia consistente o una ventana de menor carga; reducir el intervalo no garantiza
evitar un recorrido completo. No se añaden índices en esta actualización.
Use el backup de SQLite para una copia consistente, no copie a ciegas una base
activa con WAL. La lectura también consume CPU/E/S y puede retrasar escrituras.

## Integrar la plantilla en el dashboard

1. Conserve copia de seguridad y la imagen anterior. En su repositorio de
   despliegue, compruebe `git status --short` y `git rev-parse HEAD`. La base
   prevista es `235aa874538c2c044b89d733ad64fa3ab194365a`.
2. Si usa el paquete, aplique el parche desde la raíz del repositorio:

   ```sh
   git apply --check /ruta/paquete/honeypot-informe-v2.patch
   git apply /ruta/paquete/honeypot-informe-v2.patch
   git diff --stat
   ```

   Si hay cambios locales o commits posteriores, revise y adapte el parche;
   no sobrescriba personalizaciones. También puede integrar el cambio mediante
   el flujo de revisión Git habitual.
3. Conserve exactamente su `.env`, nombre de proyecto, archivos y opciones
   Compose. Los ejemplos siguientes corresponden al Compose de producción de
   la base; adapte las opciones `-f` y `-p` a su despliegue:

   ```sh
   docker inspect --format '{{.Image}}' honeypot-web
   docker image tag ID_OBTENIDO honeypot-web:pre-informe-v2
   docker compose -f docker-compose.prod.yml build honeypot-web
   ```

4. En la ventana de mantenimiento, recree solo el servicio web:

   ```sh
   docker compose -f docker-compose.prod.yml up -d --no-deps honeypot-web
   docker compose -f docker-compose.prod.yml ps
   docker logs --tail 50 honeypot-web
   ```

   La recreación puede interrumpir brevemente la ingesta; los agentes de la base
   no garantizan reenvío de todos los eventos fallidos. Si no puede aceptar esa
   interrupción, use la generación temporal anterior. No ejecute `down -v`, no
   elimine volúmenes ni vuelva a ejecutar el instalador inicial. El arranque
   original sincroniza el administrador desde el entorno: conserve las variables.
5. Compruebe `/api/health`, la recepción de eventos y el acceso al dashboard.
   En Resumen, descargue el informe y valide período, muestras y rankings.
   El endpoint continúa siendo `/dashboard/api/executive-report.pdf`.
   Si Nginx conserva la IP anterior del contenedor y devuelve 502, valide y
   recargue su configuración con los comandos de su instalación; en el Compose
   base, `docker exec honeypot-nginx nginx -t` y después
   `docker exec honeypot-nginx nginx -s reload`.

Se conserva la protección por sesión y activación del dashboard: 401 sin sesión,
404 con dashboard deshabilitado, 400 para fechas inválidas y 503 ante error o
presupuesto SQLite excedido. Las respuestas PDF mantienen `no-store` y `nosniff`.

## Reversión

La generación temporal no modifica el proceso web: deje de usar el módulo.
Para revertir el parche si no existen cambios posteriores en esos archivos:

```sh
git apply --reverse --check /ruta/paquete/honeypot-informe-v2.patch
git apply --reverse /ruta/paquete/honeypot-informe-v2.patch
docker compose -f docker-compose.prod.yml build honeypot-web
docker compose -f docker-compose.prod.yml up -d --no-deps honeypot-web
```

Puede restaurar la imagen guardada mediante un override temporal de Compose que
asigne `honeypot-web:pre-informe-v2` al servicio y `up -d --no-deps --no-build`,
conservando archivos base y nombre de proyecto. Verifique salud e ingesta.
No requiere restaurar ni eliminar datos. No se ha desplegado desde Codex.

## Validación y demostración reproducibles

Con Python 3.12 y las dependencias del proyecto en un entorno de pruebas:

```sh
python -m pip install -r app/requirements.txt
python -m pip install pypdf==6.18.0
python -m unittest discover -s tests -v
python tests/build_report_demo.py --output informe-demo.pdf
```

`pypdf` es solo una dependencia de pruebas; no se agrega a producción. El
generador de demostración usa una base temporal sintética y la elimina al acabar.
Las 20 pruebas verifican fechas, comparación, autenticación, permisos de lectura,
bloqueos, presupuesto de consultas, PDF vacío, rankings, procedencia de la
confianza, valores inválidos, evidencia del período y límites de página con
textos largos. La muestra PDF se revisó también renderizada a imágenes.

Esta actualización modifica el generador, el texto del formulario y esta guía;
añade pruebas, generador de ejemplo y referencia desde README. No cambia la
ingesta, Nginx, agentes, modelo, credenciales ni configuración de despliegue.
