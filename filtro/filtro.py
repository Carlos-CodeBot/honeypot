import os
import csv
import re

RUTA_LOGS = "./otros"
CSV_SALIDA = "base_datos_ataques.csv"
UMBRAL_NIVEL_ATAQUE = 5

# Regex para extraer datos
regex_action = re.compile(r"action:\s*['\"]?(\w+)")
regex_url = re.compile(r"url:\s*['\"]?(.+?)['\"]?$")
regex_id = re.compile(r"id:\s*['\"]?(\d{3})")
regex_level = re.compile(r"Level:\s*['\"]?(\d{1,2})")

def procesar_archivo(ruta):
    ataques = []
    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        lineas = f.readlines()

    bloques = []
    bloque_actual = []

    for linea in lineas:
        if linea.startswith("**Phase 1:"):
            if bloque_actual:
                bloques.append(bloque_actual)
                bloque_actual = []
        bloque_actual.append(linea)

    if bloque_actual:
        bloques.append(bloque_actual)

    for bloque in bloques:
        action = url = codigo = nivel = None

        for linea in bloque:
            if action is None:
                m = regex_action.search(linea)
                if m:
                    action = m.group(1)

            if url is None:
                m = regex_url.search(linea)
                if m:
                    url = m.group(1)

            if codigo is None:
                m = regex_id.search(linea)
                if m:
                    codigo = m.group(1)

            if nivel is None:
                m = regex_level.search(linea)
                if m:
                    nivel = int(m.group(1))

       # print("-------- BLOQUE --------")
       # print(f"Método: {action} | URL: {url} | Código: {codigo} | Nivel: {nivel}")
       # print("------------------------")

        if nivel is not None and nivel >= UMBRAL_NIVEL_ATAQUE:
            ataques.append([action or "N/A", url or "N/A", codigo or "N/A"])

    return ataques

def procesar_todos():
    datos = []
    for archivo in os.listdir(RUTA_LOGS):
        if archivo.endswith(".txt"):
            ruta = os.path.join(RUTA_LOGS, archivo)
            print(f"[Procesando] {archivo}")
            datos += procesar_archivo(ruta)
    return datos

def guardar_csv(datos):
    with open(CSV_SALIDA, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Metodo", "Cuerpo_Peticion", "Codigo_Respuesta"])
        writer.writerows(datos)
    print(f"[✔] CSV guardado con {len(datos)} ataques: {CSV_SALIDA}")

if __name__ == "__main__":
    ataques = procesar_todos()
    guardar_csv(ataques)

