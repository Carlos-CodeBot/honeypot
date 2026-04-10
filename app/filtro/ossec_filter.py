#!/usr/bin/env python3
import argparse
import csv
import re
from typing import List

UMBRAL_NIVEL_ATAQUE = 5

regex_action = re.compile(r"action:\s*['\"]?(\w+)", re.IGNORECASE)
regex_url = re.compile(r"url:\s*['\"]?(.+?)['\"]?$", re.IGNORECASE)
regex_id = re.compile(r"id:\s*['\"]?(\d{3})", re.IGNORECASE)
regex_level = re.compile(r"level:\s*['\"]?(\d{1,2})", re.IGNORECASE)


def split_blocks(lines: List[str]) -> List[List[str]]:
    blocks = []
    current = []
    for line in lines:
        if line.startswith("**Phase 1:") and current:
            blocks.append(current)
            current = []
        current.append(line)
    if current:
        blocks.append(current)
    return blocks


def parse_block(block: List[str]):
    action = None
    url = None
    code = None
    level = None

    for line in block:
        if action is None:
            m = regex_action.search(line)
            if m:
                action = m.group(1).upper()

        if url is None:
            m = regex_url.search(line)
            if m:
                url = m.group(1).strip()

        if code is None:
            m = regex_id.search(line)
            if m:
                code = m.group(1)

        if level is None:
            m = regex_level.search(line)
            if m:
                level = int(m.group(1))

    if level is not None and level >= UMBRAL_NIVEL_ATAQUE:
        return [action or "N/A", url or "N/A", code or "N/A"]
    return None


def filter_ossec_file(input_path: str, output_path: str) -> int:
    with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
        lines = infile.readlines()

    rows = []
    for block in split_blocks(lines):
        parsed = parse_block(block)
        if parsed:
            rows.append(parsed)

    with open(output_path, "w", encoding="utf-8", newline="") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["Metodo", "Cuerpo_Peticion", "Codigo_Respuesta"])
        writer.writerows(rows)

    return len(rows)


def main():
    parser = argparse.ArgumentParser(description="Filtra output de OSSEC y genera CSV para entrenamiento")
    parser.add_argument("--input", required=True, help="Ruta del archivo txt de entrada")
    parser.add_argument("--output", required=True, help="Ruta del CSV de salida")
    args = parser.parse_args()

    total = filter_ossec_file(args.input, args.output)
    print(f"rows_written={total}")


if __name__ == "__main__":
    main()
