#!/usr/bin/env python3
"""
CiberGabs SOC Lab — dispara el escenario de ataque contra el SOC del lab.

Es lo mismo que el botón «Lanzar ataque» del dashboard, pero desde la terminal
(útil para automatizar o para correrlo en bucle). No ataca nada externo: solo le
pide al SOC del lab que reproduzca la noche (soc/scenario.py).

Uso:
    python attack.py              # ataque normal
    python attack.py injection    # el atacante deja una nota para tu agente de IA

Variables:
    SOC_URL   default http://soc:8080
    REPLAY    segundos entre repeticiones (0 = una sola vez)
    DURATION  segundos reales que dura la noche simulada (default 24)
"""
import os
import sys
import time

import requests

SOC = os.environ.get("SOC_URL", "http://soc:8080").rstrip("/")
REPLAY = int(os.environ.get("REPLAY", "0"))
DURATION = float(os.environ.get("DURATION", "24"))
VARIANT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VARIANT", "base")


def wait_soc() -> None:
    for _ in range(60):
        try:
            requests.get(f"{SOC}/api/attack/status", timeout=2)
            return
        except requests.RequestException:
            time.sleep(1)
    sys.exit("El SOC no responde en " + SOC)


def run_once() -> None:
    r = requests.post(f"{SOC}/api/attack", params={"variant": VARIANT, "duration": DURATION}, timeout=5).json()
    print(f"[attacker] escenario '{VARIANT}': {r}", flush=True)
    while requests.get(f"{SOC}/api/attack/status", timeout=5).json().get("running"):
        time.sleep(1)
    print("[attacker] terminado. Abre http://localhost:8080", flush=True)


if __name__ == "__main__":
    wait_soc()
    run_once()
    while REPLAY > 0:
        time.sleep(REPLAY)
        run_once()
