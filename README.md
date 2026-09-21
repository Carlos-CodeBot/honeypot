# Honeypot Web + Dashboard SOC

Herramienta educativa de honeypot web con clasificación de ataques HTTP (reglas + ML), panel SOC para análisis, entrenamiento adaptativo y arquitectura Agent/Server donde el agente se instala sobre el Nginx del cliente para reenviar tráfico al honeypotserver central con ingesta segura.

El dashboard permite descargar un informe ejecutivo PDF con top 10 de IP, países
y tipos de ataque, ejemplos de los registros y confianza separada entre IA y reglas.
Consulte la [guía de informes](docs/INFORME_PDF.md) para metodología, limitaciones,
actualización y generación sin reiniciar el servicio.

Los administradores pueden configurar [informes semanales por correo](docs/INFORMES_CORREO.md)
desde el dashboard, con SMTP Microsoft 365 o Graph, credenciales cifradas y un
servicio independiente para la programación y la cola de envíos.
