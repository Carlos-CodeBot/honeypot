# Informes semanales por correo

La pestaña **Informes por correo** aparece para administradores del dashboard.
Permite configurar remitente Microsoft 365, contraseña SMTP o aplicación Graph,
destinatarios, día, hora y zona horaria; activar/desactivar la programación;
enviar una prueba con PDF y consultar los últimos 20 resultados.

No se activa ningún envío al instalar. Primero configure la cuenta desde el
dashboard y guarde. Las credenciales no se incluyen en Git, en el HTML ni en las
respuestas de consulta; los campos secretos quedan vacíos después de guardar.

## Cuenta Microsoft

### Correo y contraseña (SMTP)

Seleccione SMTP, introduzca el correo empresarial y la contraseña del buzón.
El remitente se usa también como usuario de autenticación. El servidor y puerto
son fijos: `smtp.office365.com:587`, con STARTTLS obligatorio y validación del
certificado. No admite conexiones sin cifrar ni cambiar el destino de la credencial.

El buzón debe tener permitido SMTP AUTH y la autenticación utilizada. Una cuenta
sin MFA no garantiza por sí sola que SMTP AUTH esté habilitado. No se modifica
ninguna política de Microsoft desde el honeypot. Ante rechazo, el historial
mostrará un error de autenticación sin revelar la respuesta sensible del proveedor.

Microsoft anunció que el comportamiento de SMTP AUTH Basic permanece sin cambios
hasta diciembre de 2026, con cambios posteriores y retirada futura. Por eso se
incluye también Graph para migrar sin cambiar la programación:
[calendario oficial](https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835),
[configuración de envío de aplicaciones](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365).

### Microsoft Graph / OAuth

Configure una aplicación en Microsoft Entra con autorización de aplicación para
enviar desde el buzón. La configuración administrativa requiere permisos adecuados
en Microsoft 365. Introduzca en la pestaña el remitente, Tenant ID, Client ID y
**valor** del secreto de aplicación (no el identificador del secreto).

Microsoft documenta `Mail.Send` para `sendMail`. Restrinja el acceso al buzón
dedicado mediante la configuración de Exchange correspondiente. Si utiliza RBAC
para aplicaciones, evite mantener simultáneamente una concesión global sin
restricciones: los permisos pueden ser aditivos. Revise el alcance efectivo con
su administrador. El secreto tiene caducidad; sustitúyalo desde el formulario.

[sendMail y adjuntos](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0),
[RBAC para aplicaciones](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac).

El servicio necesita salida DNS/TLS a Microsoft: puerto 587 para SMTP o HTTPS
443 a `login.microsoftonline.com` y `graph.microsoft.com` para Graph. La versión
actual apunta a Microsoft 365 comercial global, no nubes soberanas ni Exchange local.

## Funcionamiento

- El envío automático está desactivado inicialmente. Valor inicial del horario:
  lunes a las 07:00, `America/Bogota`; ambos se pueden cambiar en el formulario.
- El horario usa la zona elegida. El PDF mantiene la metodología del generador:
  semana calendario anterior, de lunes a domingo completos **en UTC**. Por ejemplo,
  un envío del lunes 21/09/2026 cubre 14/09/2026 a 20/09/2026.
- La prueba y el envío manual incluyen un PDF real de ese período y se envían a
  **todos los destinatarios guardados**. La prueba añade `[PRUEBA]` al asunto.
  Use inicialmente su propia dirección como destinatario para comprobar el flujo.
- Cada petición queda en una cola persistente. El worker la revisa cada 15 segundos.
  Solo permite un trabajo en preparación/envío a la vez, incluso con dos workers.
  Los clics repetidos se bloquean mientras exista trabajo pendiente y durante un
  minuto desde la solicitud anterior.
- Cada semana automática tiene una clave única: reiniciar el servicio no vuelve
  a enviar una semana ya registrada. Tras una parada prolongada recupera solo
  la última semana vencida; no envía una avalancha de informes históricos.
- Cambiar y guardar la configuración cancela los trabajos aún en cola. Los que
  ya están en preparación o envío pueden terminar con la configuración anterior.
  Desactivar elimina la próxima ejecución; no recupera un correo ya enviado.
- No reintenta automáticamente entregas: una desconexión puede ocurrir después
  de que Microsoft acepte el mensaje. Los trabajos interrumpidos en preparación
  quedan fallidos y los interrumpidos durante envío quedan inciertos al vencer
  15 minutos. Revise el buzón y solicite un envío manual si corresponde.
- “Aceptado por Microsoft” no equivale a entrega final. Compruebe devoluciones,
  spam o trazabilidad de mensajes si el destinatario no lo recibe. SMTP puede
  aceptar solo algunos destinatarios; se muestra un estado parcial.

El worker crea una copia consistente de `honeypot.db` mediante SQLite Backup,
cierra la conexión de origen y genera el PDF sobre la copia. Una transacción de
lectura fija la vista de origen para que las escrituras concurrentes no reinicien
la copia por bloques. En modo WAL, el presupuesto de copia es 60 s; otros modos
usan 2 s para limitar cuánto se retienen las confirmaciones de escritura. No se
cambia automáticamente el modo de la base. Si una base sin WAL no puede copiarse
en ese margen, el historial lo indica: planifique una ventana de baja actividad
o una migración controlada a WAL, considerando sus respaldos y almacenamiento.
Las consultas sobre la copia tienen un presupuesto de 120 s.
La copia temporal se elimina al finalizar, incluso al fallar. Límite
del PDF adjunto: 2 MiB. No inicia `app.py`, el modelo ni el lector personalizado.

## Persistencia y credenciales

Los archivos nuevos están dentro del volumen existente:

```text
/data/report-mail/settings.sqlite3
/data/report-mail/credentials.key
```

La base contiene configuración, cola, historial y credenciales cifradas con
Fernet. La clave se genera al guardar por primera vez. En Linux, el directorio
usa permisos 0700 y los archivos sensibles 0600. El acceso root al volumen y a
la clave permite descifrar: el cifrado no protege frente a un servidor comprometido.
La clave y la base deben respaldarse juntas y mantenerse fuera de Git.

Nunca borre ni regenere la clave para solucionar un fallo: perderla impide recuperar
las credenciales. Restaure su copia o vuelva a configurar una instalación nueva
de forma controlada. Los trabajos terminales dejan de conservar su copia cifrada
de la credencial; la configuración actual la mantiene.

Acceda al dashboard por HTTPS o un canal privado cifrado antes de introducir
credenciales: STARTTLS protege la conexión del servidor a Microsoft, no el tramo
del navegador al dashboard. Solo los administradores acceden a esta API; las
escrituras requieren un token CSRF de sesión. La actualización también convierte
los valores de logs/candidatos/usuarios en texto de DOM, evitando interpretar
peticiones capturadas como HTML en la misma página que configura credenciales.

## Instalación en dckcyber01

Mantenga `/home/adm0n/honeypot`, proyecto Compose `honeypot`, archivo personalizado
`docker-compose.prod.yml`, `.env`, `.envn`, `collector/` y lector local existentes.
El parche añade solamente el registro del módulo de correo en `app.py`; no
reemplaza el archivo ni modifica el lector. Añade un overlay de Compose, sin
reescribir el Compose de producción. No ejecute `git reset --hard` o `down -v`.

1. Respalde archivos, imagen y SQLite como en la actualización anterior.
2. Aplique el parche del paquete desde el repositorio, conservando los cambios
   locales. `git apply --check` debe pasar antes de aplicar; si no encaja, revise
   el conflicto en lugar de sobrescribir archivos.
3. Construya las imágenes con las nuevas dependencias (`cryptography` y `tzdata`):

   ```bash
   cd /home/adm0n/honeypot
   docker compose -p honeypot -f docker-compose.prod.yml -f docker-compose.report-mail.yml build honeypot-web honeypot-report-mail
   ```

4. En su ventana de actualización, recree únicamente el web usando el Compose
   original. **Su lector activo puede volver a leer logs si sigue usando
   `position = 0`.** La instalación inicial exige este reinicio; los futuros
   cambios de correo desde el dashboard no lo exigen.

   ```bash
   docker compose -p honeypot -f docker-compose.prod.yml up -d --no-deps --no-build --force-recreate honeypot-web
   docker exec honeypot-nginx nginx -t && docker exec honeypot-nginx nginx -s reload
   ```

5. Inicie el servicio independiente:

   ```bash
   docker compose -p honeypot -f docker-compose.prod.yml -f docker-compose.report-mail.yml up -d --no-deps honeypot-report-mail
   docker logs --tail 30 honeypot-report-mail
   ```

   El overlay usa como volumen externo `honeypot_honeypot-data`, que ya existe
   en esta instalación. Si cambió, configure `REPORT_DATA_VOLUME` con el nombre
   real antes de estos comandos. El worker usa `/data/honeypot.db`; adapte esa
   ruta si su despliegue utiliza otra base. No crea un volumen vacío sustituto.

6. Entre como administrador, abra **Informes por correo**, guarde sus datos y
   envíe una prueba. El indicador del servicio debe estar activo. Espere el
   resultado en Actividad y confirme la recepción del PDF antes de activar el
   horario semanal. Nunca comparta contraseñas en el chat o en capturas.

El ZIP incluye `scripts/instalar-informes-correo.sh`, que realiza los respaldos,
aplica el parche del paquete, construye, recrea y arranca el worker. Por defecto
prepara sin reiniciar si detecta el lector activo. `--accept-log-replay` permite
completar la recreación aceptando su posible relectura. `--prepare-only` siempre
se detiene antes de recrear o iniciar servicios. Está destinado al despliegue
descrito; no modifica un servidor remoto desde Codex.

## Reversión

### Corrección de `TimeoutError: snapshot` en instalaciones existentes

El archivo autónomo `scripts/corregir-snapshot-correo.sh` contiene el parche del
módulo. Ejecútelo con `bash corregir-snapshot-correo.sh` tras copiarlo al servidor.
Respalda el módulo y etiqueta la imagen anterior, aplica solo ese cambio,
construye la imagen del servicio de correo y prueba copia/PDF sobre el volumen
real sin conexión de red. Solo si la prueba pasa recrea `honeypot-report-mail`.
No reinicia web ni el lector. No necesita el ZIP anterior ni aplica el README.
Si encuentra una entrega en preparación/envío, se detiene antes de recrear;
espere a que termine antes de repetir. No reenvía los trabajos fallidos.

El script puede detenerse con el error específico de presupuesto si la base es
demasiado grande/lenta para el modo de journal actual; conserva el servicio
anterior. No activa WAL ni amplía bloqueos de escritura automáticamente.

### Revertir la instalación completa

Desactive el envío en la pestaña y detenga `honeypot-report-mail`. Si debe retirar
el código, aplique el parche en reversa solo si `git apply --reverse --check` pasa,
y restaure la imagen web guardada conservando el Compose y volumen existentes.
La recreación de web mantiene el mismo riesgo de relectura del lector personalizado.
No restaure una base antigua de eventos ni borre el volumen. Conserve la carpeta
`/data/report-mail` para poder recuperar configuración e historial.

## Validación

Pruebas unitarias/integración de permisos, CSRF, cifrado, secretos omitidos,
horario/DST, reinicios, concurrencia, período semanal, copia SQLite, SMTP STARTTLS,
adjunto PDF, Graph y errores inciertos. Las pruebas de envío simulan Microsoft;
no utilizan credenciales ni envían correos reales. La pantalla se prueba en un
dashboard local y en tamaños de escritorio y móvil. La aceptación por su tenant
se comprueba con **Enviar prueba con PDF** una vez instalado y configurado.

```bash
python -m pip install -r app/requirements.txt
python -m pip install pypdf
python -m unittest discover -s tests -v
```
