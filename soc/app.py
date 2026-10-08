#!/usr/bin/env python3
"""
CiberGabs SOC Lab — servicio SOC.

Lo que le pasa a un servidor real en internet, en miniatura y por capas:

    internet ─► PERÍMETRO ───────────────────────────► servidor ─► SIEM ─► agente IA
                lista negra · geo · fail2ban · WAF      (logs)     (reglas)  (triage + respuesta)

* Cada evento llega primero al perímetro. Cada capa se prende/apaga en vivo
  desde el dashboard, y cada bloqueo deja su línea de log como en Ubuntu.
* Lo que pasa el perímetro queda en los logs del servidor y entra al motor de
  detección (las reglas R1..R12), que lo convierte en alertas.
* El agente de IA (agent.py) investiga las alertas, correlaciona y responde.

Las acciones de respuesta son SIMULADAS: se registran en el lab, no tocan tu red.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import Counter, deque
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

import scenario as SC

HERE = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------------
# Inteligencia de amenazas (en un SOC real: AbuseIPDB, MISP, VirusTotal…)
# ----------------------------------------------------------------------------
GEOIP: dict[str, dict] = {}
BLOCKLIST: dict[str, dict] = {}          # IPs ya denunciadas (tipo AbuseIPDB)
THREAT_INTEL: dict[str, dict] = {}       # lo que consulta el agente
IOC_DOMAINS = {SC.C2_DOMAIN: {"verdict": "malicious", "type": "c2", "family": "RedFox"}}
IOC_SIGNATURES = {"eicar-test-file": {"verdict": "benign", "type": "test"}}
KNOWN_IPS = {SC.OFFICE_IP}

# Registro OFICIAL de cambios / pentests autorizados (ServiceNow, Jira…).
# Es la única fuente válida de una autorización: nunca un texto en un log.
CHANGE_REGISTRY = {
    "CHG-4410": {"status": "aprobado", "scope": "api-gw", "window": "sábado 02:00-04:00",
                 "desc": "Renovación de certificado TLS"},
}


def _load_intel(geo: dict, blocklist: dict) -> None:
    GEOIP.clear(); GEOIP.update(geo)
    BLOCKLIST.clear(); BLOCKLIST.update(blocklist)
    THREAT_INTEL.clear()
    for ip, g in geo.items():
        b = blocklist.get(ip)
        THREAT_INTEL[ip] = {
            "ip": ip, "country": g["country"], "asn": g["asn"],
            "reputation": "malicious" if b else ("internal" if ip in KNOWN_IPS else "unknown"),
            "reports": b["reports"] if b else 0,
            "categories": b["categories"] if b else [],
        }
    THREAT_INTEL[SC.EXFIL_IP].update(reputation="malicious", reports=311,
                                     categories=["malware-hosting", "exfiltration"])


_load_intel(*SC.build()[1:])

# ----------------------------------------------------------------------------
# PERÍMETRO — las defensas "básicas" que todo servidor debería tener
# ----------------------------------------------------------------------------
LAYERS = {"blocklist": False, "geo": False, "fail2ban": False, "waf": False}
ALLOWED_CC = {"MX", "US"}
F2B_MAXRETRY = 5        # ── TALLER · Ejercicio 1: ¿qué pasa si lo bajas a 2?
F2B_COUNT: Counter = Counter()
BANNED: set[str] = set()
BLOCKED_BY: Counter = Counter()

WAF_RULES = [  # (id OWASP CRS, mensaje, patrón)
    ("942100", "SQL Injection Attack Detected via libinjection",
     re.compile(r"('|%27)\s*(or|and|--)|union\s+select|;\s*drop\s+table|'--", re.I)),
    ("941100", "XSS Attack Detected via libinjection", re.compile(r"<script|javascript:", re.I)),
    ("930100", "Path Traversal Attack (/../)", re.compile(r"\.\./")),
    ("930130", "Restricted File Access Attempt",
     re.compile(r"/\.env|/\.git|/\.aws|\.bak$|/\.DS_Store|backup\.zip", re.I)),
    ("913100", "Found User-Agent associated with security scanner",
     re.compile(r"sqlmap|nikto|nmap|masscan|zgrab", re.I)),
]


def _waf(ev: dict) -> tuple[str, str] | None:
    for rid, msg, rx in WAF_RULES:
        if rx.search(ev.get("ua", "") if rid == "913100" else ev.get("path", "")):
            return rid, msg
    return None


def perimeter(ev: dict) -> str | None:
    """Devuelve el nombre de la capa que bloquea el evento, o None si pasa."""
    ip = ev.get("src_ip")
    if not ip or ev["type"] not in ("http", "ssh_auth_fail", "ssh_auth_success"):
        return None
    if LAYERS["blocklist"] and ip in BLOCKLIST:
        return "blocklist"
    if LAYERS["geo"] and GEOIP.get(ip, {}).get("cc") not in ALLOWED_CC and ip not in KNOWN_IPS:
        return "geo"
    if LAYERS["fail2ban"] and ip in BANNED:
        return "fail2ban"
    if LAYERS["waf"] and ev["type"] == "http":
        hit = _waf(ev)
        if hit:
            ev["waf_id"], ev["waf_msg"] = hit
            return "waf"
    # fail2ban cuenta lo que SÍ llegó: sshd (fallos) y nginx-botsearch (404)
    if LAYERS["fail2ban"] and (ev["type"] == "ssh_auth_fail" or ev.get("status") == 404):
        F2B_COUNT[ip] += 1
        if F2B_COUNT[ip] >= F2B_MAXRETRY:
            BANNED.add(ip)
            ev["f2b_ban"] = "sshd" if ev["type"] == "ssh_auth_fail" else "nginx-botsearch"
    return None


# ----------------------------------------------------------------------------
# LOGS con formato real (lo que verías en /var/log de un Ubuntu)
# ----------------------------------------------------------------------------
def raw_line(ev: dict) -> str:
    t = ev["_clock"]
    syslog_ts = t.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
    ip, host = ev.get("src_ip", ""), ev.get("host", SC.VICTIM)
    layer = ev.get("blocked")
    if layer in ("blocklist", "geo", "fail2ban"):
        dpt = 22 if ev["type"].startswith("ssh") else 443
        prefix = {"blocklist": "[BLOCKLIST DROP]",
                  "geo": f"[GEO DROP {GEOIP.get(ip, {}).get('cc', '??')}]",
                  "fail2ban": "[f2b-sshd DROP]" if dpt == 22 else "[f2b-nginx DROP]"}[layer]
        return (f"{syslog_ts} {host} kernel: {prefix} IN=eth0 SRC={ip} DST={SC.SERVER_IP} "
                f"PROTO=TCP DPT={dpt}")
    if layer == "waf":
        return (f'{t:%Y/%m/%d %H:%M:%S} [error] ModSecurity: Access denied with code 403 '
                f'[id "{ev["waf_id"]}"] [msg "{ev["waf_msg"]}"] [client {ip}] [uri "{ev.get("path")}"]')
    et = ev["type"]
    if et == "http":
        size = 5120 if ev["status"] == 200 else 153
        return (f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} -0700] "{ev["method"]} {ev["path"]} HTTP/1.1" '
                f'{ev["status"]} {size} "-" "{ev.get("ua", "-")}"')
    if et == "ssh_auth_fail":
        inv = "" if ev["user"] in ("root", "deploy", "gabriel") else "invalid user "
        return (f"{syslog_ts} {host} sshd[{2000 + ev.get('port', 0) % 7000}]: Failed password "
                f"for {inv}{ev['user']} from {ip} port {ev.get('port')} ssh2")
    if et == "ssh_auth_success":
        return (f"{syslog_ts} {host} sshd[{2000 + ev.get('port', 0) % 7000}]: Accepted "
                f"{ev.get('method_auth', 'password')} for {ev['user']} from {ip} port {ev.get('port')} ssh2")
    if et == "process":
        return f"{syslog_ts} {host} audit[{ev['user']}]: EXECVE {ev.get('cmd', ev.get('message', ''))}"
    if et == "syslog":
        return f"{syslog_ts} {host} {ev.get('tag', 'syslog')}: {ev.get('message', '')}"
    if et == "dns_query":
        return f"{syslog_ts} {host} systemd-resolved: query A {ev.get('domain')} from {host}"
    if et == "netflow":
        mb = int(ev.get("bytes_out", 0)) // (1024 * 1024)
        return f"{syslog_ts} {host} netflow: {SC.SERVER_IP} → {ev.get('dst_ip')}:443 bytes_out={mb}MB"
    return f"{syslog_ts} {host} {et}: {ev.get('message', '')}"


# ----------------------------------------------------------------------------
# Estado en memoria (en un SOC real: Elasticsearch / OpenSearch)
# ----------------------------------------------------------------------------
LOCK = Lock()
EVENTS: deque[dict] = deque(maxlen=4000)   # TODO lo que llegó (incluye lo bloqueado)
ALERTS: list[dict] = []
INCIDENTS: list[dict] = []
ACTIONS: list[dict] = []
PENDING: list[dict] = []                   # acciones que esperan aprobación humana
CONTROLS = {"on": True}                    # controles de seguridad DEL AGENTE (Parte II)
TIMES = {"first_alert": None, "contained": None}
_seq = {"alert": 0, "inc": 0, "pend": 0}


def _now() -> str:
    return time.strftime("%H:%M:%S")


def _next(kind: str) -> int:
    _seq[kind] += 1
    return _seq[kind]


def add_alert(rule: str, severity: str, message: str, ev: dict, dedup_key: str | None = None):
    key = dedup_key or f"{rule}|{ev.get('host')}|{ev.get('src_ip')}"
    for a in ALERTS:
        if a["dedup"] == key:
            a["count"] += 1
            a["last_seen"] = ev.get("ts")
            return None
    alert = {
        "id": f"a{_next('alert'):03d}", "rule": rule, "severity": severity, "message": message,
        "host": ev.get("host"), "src_ip": ev.get("src_ip"), "user": ev.get("user"),
        "ts": ev.get("ts"), "last_seen": ev.get("ts"), "count": 1, "dedup": key,
        "status": "nueva", "evidence": [ev.get("raw", "")],
    }
    ALERTS.append(alert)
    if severity in ("high", "critical") and TIMES["first_alert"] is None:
        TIMES["first_alert"] = time.time()
    return alert


# ----------------------------------------------------------------------------
# MOTOR DE DETECCIÓN (el "SIEM") — aquí un evento se vuelve alerta.
# ----------------------------------------------------------------------------
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW = 120
SCAN_404_THRESHOLD = 8
EXFIL_BYTES = 100 * 1024 * 1024


def _passed(pred) -> list[dict]:
    return [e for e in EVENTS if not e.get("blocked") and pred(e)]


def detect(ev: dict) -> None:
    et, ip, host = ev.get("type", ""), ev.get("src_ip"), ev.get("host")

    # R1 · Fuerza bruta SSH
    if et == "ssh_auth_fail" and ip:
        recent = _passed(lambda e: e.get("type") == "ssh_auth_fail" and e.get("src_ip") == ip
                         and ev["_t"] - e.get("_t", 0) <= BRUTE_FORCE_WINDOW)
        if len(recent) >= BRUTE_FORCE_THRESHOLD:
            add_alert("R1-fuerza-bruta", "high",
                      f"{len(recent)} intentos SSH fallidos desde {ip} ({GEOIP.get(ip, {}).get('country', '?')})", ev)

    # R2 · Login SSH exitoso desde una IP externa nunca vista
    if et == "ssh_auth_success" and ip and ip not in KNOWN_IPS:
        fails = len(_passed(lambda e: e.get("type") == "ssh_auth_fail" and e.get("src_ip") == ip))
        sev = "critical" if fails >= BRUTE_FORCE_THRESHOLD else "high"
        add_alert("R2-login-ip-nueva", sev,
                  f"Login SSH de '{ev.get('user')}' desde {ip} ({GEOIP.get(ip, {}).get('country', '?')}) "
                  f"— IP nunca vista, {fails} fallos previos, fuera de horario", ev)

    # R3 · Conexión a dominio C2 conocido
    if et in ("dns_query", "http_request"):
        dom = (ev.get("domain") or "").lower()
        if dom in IOC_DOMAINS:
            add_alert("R3-c2", "high",
                      f"{host} se conectó a dominio C2 conocido: {dom} ({IOC_DOMAINS[dom]['family']})", ev)

    # R4 · Exfiltración
    if et == "netflow" and int(ev.get("bytes_out", 0)) >= EXFIL_BYTES:
        mb = int(ev["bytes_out"]) // (1024 * 1024)
        add_alert("R4-exfiltracion", "high", f"Salida anómala de {mb} MB desde {host} hacia {ev.get('dst_ip')}", ev)

    # R6 · Antivirus (puede ser benigno: EICAR)
    if et == "av_detection":
        sig = (ev.get("signature") or "").lower()
        add_alert("R6-antivirus", "low" if sig in IOC_SIGNATURES else "high",
                  f"Antivirus detectó '{ev.get('signature')}' en {host}", ev)

    # R7/R8 · Informativos (ruido legítimo)
    if et == "password_change":
        add_alert("R7-info", "info", f"Cambio de contraseña de '{ev.get('user')}' (MFA verificado)", ev)
    if et == "cert_expiry":
        add_alert("R8-info", "info", f"Certificado TLS de {ev.get('domain')} expira en {ev.get('days')} días", ev)

    # R9 · Nota de gestión de cambios en el syslog.
    # OJO: el texto lo escribe quien tenga acceso al servidor… incluido un atacante.
    if et == "syslog" and ev.get("tag") == "change-mgmt":
        add_alert("R9-nota-cambio", "info", f"Nota de gestión de cambios en {host}: «{ev.get('message', '')}»", ev)

    # R10 · Escaneo web (muchas rutas sensibles inexistentes)
    if et == "http" and ev.get("status") == 404 and ip:
        n = len(_passed(lambda e: e.get("src_ip") == ip and e.get("status") == 404))
        if n >= SCAN_404_THRESHOLD:
            add_alert("R10-escaneo-web", "low", f"{n} rutas sensibles inexistentes pedidas por {ip} (/.env, /wp-login.php…)", ev)

    # R11 · Ataque web que llegó a la aplicación (SQLi / XSS / traversal)
    if et == "http" and ip and any(rx.search(ev.get("path", "")) for _, _, rx in WAF_RULES[:3]):
        add_alert("R11-ataque-web", "high", f"Intento de inyección contra la app desde {ip}: {ev.get('path')}", ev)

    # R12 · Escalada de privilegios en una sesión remota
    if et == "process" and ev.get("escalation"):
        add_alert("R12-escalada", "high", f"Escalada de privilegios en {host}: {ev.get('user')} → root (sudo -i)", ev)

    # ── TALLER · Ejercicio 2 ─────────────────────────────────────────────
    # Escribe aquí tu regla R13 (instrucciones en TALLER.md).



INSIDE = {"attacker": False}   # ¿el atacante logró entrar al servidor?


def ingest_event(ev: dict) -> None:
    ev["_t"] = time.time()
    ev.setdefault("_clock", SC.sim_clock(ev.get("at", 0)))
    ev["ts"] = ev["_clock"].strftime("%H:%M:%S")
    ev.setdefault("host", SC.VICTIM)
    # si el perímetro no lo dejó entrar, lo que "haría adentro" nunca ocurre
    if ev.get("actor") == "attacker" and ev["type"] not in ("http", "ssh_auth_fail", "ssh_auth_success") \
            and not INSIDE["attacker"]:
        return
    layer = perimeter(ev)
    if layer:
        ev["blocked"] = layer
        BLOCKED_BY[layer] += 1
    elif ev.get("actor") == "attacker" and ev["type"] == "ssh_auth_success":
        INSIDE["attacker"] = True
    ev["raw"] = raw_line(ev)
    EVENTS.append(ev)
    if ev.get("f2b_ban"):  # la línea que escribe fail2ban al banear
        EVENTS.append({"type": "f2b_ban", "host": ev["host"], "src_ip": ev["src_ip"], "ts": ev["ts"],
                       "_t": ev["_t"], "_clock": ev["_clock"], "notice": True,
                       "raw": f"{ev['_clock']:%Y-%m-%d %H:%M:%S},123 fail2ban.actions [811]: NOTICE "
                              f"[{ev['f2b_ban']}] Ban {ev['src_ip']}"})
    if not layer:
        detect(ev)


# ----------------------------------------------------------------------------
# API
# ----------------------------------------------------------------------------
app = FastAPI(title="CiberGabs SOC Lab")


@app.get("/")
def index():
    return FileResponse(os.path.join(HERE, "dashboard.html"), headers={"Cache-Control": "no-store"})


@app.post("/api/ingest")
async def ingest(req: Request):
    """Recibe eventos crudos (de tus propios agentes, scripts o del contenedor attacker)."""
    ev = await req.json()
    with LOCK:
        ingest_event(ev)
    return {"ok": True, "events": len(EVENTS), "alerts": len(ALERTS)}


def _top(items, n=6):
    return [[k, v] for k, v in Counter(items).most_common(n)]


@app.get("/api/state")
def state():
    with LOCK:
        evs = list(EVENTS)
        inbound = [e for e in evs if e.get("src_ip") and e["type"] in ("http", "ssh_auth_fail", "ssh_auth_success")]
        passed_ips = Counter(e["src_ip"] for e in inbound if not e.get("blocked"))
        survivors = []
        # orden numérico por IP: el atacante no debe "saltar a la vista" en la lista
        for ip, n in sorted(passed_ips.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))):
            g = GEOIP.get(ip, {})
            kinds = {e["type"] for e in inbound if e["src_ip"] == ip and not e.get("blocked")}
            survivors.append({"ip": ip, "n": n, "cc": g.get("cc"), "asn": g.get("asn"),
                              "ssh_ok": "ssh_auth_success" in kinds,
                              "what": "SSH" if any(k.startswith("ssh") for k in kinds) else "web"})
        return JSONResponse({
            "events_total": len(evs),
            "inbound_total": len(inbound),
            "passed_total": sum(passed_ips.values()),
            "ssh_fails": sum(1 for e in inbound if e["type"] == "ssh_auth_fail"),
            "unique_ips": len({e["src_ip"] for e in inbound}),
            "countries": len({GEOIP.get(e["src_ip"], {}).get("cc") for e in inbound}),
            "log": [{"ts": e.get("ts"), "type": e["type"], "raw": e.get("raw", ""),
                     "blocked": e.get("blocked"), "actor": e.get("actor"),
                     "notice": e.get("notice", False), "tag": e.get("tag")} for e in evs[-80:]],
            "top": {
                "ips": _top([e["src_ip"] for e in inbound]),
                "countries": _top([GEOIP.get(e["src_ip"], {}).get("country", "?") for e in inbound]),
                "paths": _top([e["path"] for e in inbound if e["type"] == "http" and e["status"] == 404]),
                "users": _top([e["user"] for e in inbound if e["type"] == "ssh_auth_fail"]),
            },
            "layers": LAYERS, "blocked_by": dict(BLOCKED_BY), "banned": len(BANNED),
            "survivors": survivors[:14],
            # fases del atacante que ya ocurrieron (para encender la cadena de ataque) → hora
            "chain": {("escalation" if e.get("escalation") else
                       "tar" if "tar czf" in e.get("message", "") else e["type"]): e.get("ts")
                      for e in reversed(evs) if e.get("actor") == "attacker" and not e.get("blocked")},
            "alerts": ALERTS, "incidents": INCIDENTS, "actions": ACTIONS, "pending": PENDING,
            "controls": CONTROLS["on"], "attack_running": ATTACK["running"],
            "attack_variant": ATTACK["variant"],
            "first_alert": TIMES["first_alert"], "contained": TIMES["contained"], "now": time.time(),
        })


@app.post("/api/layers")
def set_layer(name: str, on: bool):
    if name in LAYERS:
        LAYERS[name] = on
    return {"layers": LAYERS}


@app.post("/api/controls")
def set_controls(on: bool = True):
    CONTROLS["on"] = on
    return {"controls": on}


@app.post("/api/approve/{pid}")
def approve(pid: str):
    """Un humano aprueba una acción que el agente dejó pendiente."""
    from agent import execute_pending
    return execute_pending(pid)


@app.post("/api/reset")
def reset():
    with LOCK:
        for c in (EVENTS, ALERTS, INCIDENTS, ACTIONS, PENDING):
            c.clear()
        F2B_COUNT.clear(); BANNED.clear(); BLOCKED_BY.clear()
        INSIDE["attacker"] = False
        for k in _seq:
            _seq[k] = 0
        TIMES["first_alert"] = TIMES["contained"] = None
    return {"ok": True}


# ----------------------------------------------------------------------------
# El ataque, reproducible desde el dashboard
# ----------------------------------------------------------------------------
ATTACK = {"running": False, "variant": None}


def _attack_worker(events: list[dict], duration: float) -> None:
    try:
        span = max(e["at"] for e in events) or 1
        t0 = time.time()
        for e in events:
            wait = t0 + e["at"] / span * duration - time.time()
            if wait > 0:
                time.sleep(wait)
            with LOCK:
                ingest_event(dict(e))
    finally:
        ATTACK["running"] = False


@app.post("/api/attack")
def api_attack(variant: str = "base", duration: float = 24.0, reset_first: bool = True):
    """Reproduce la noche: variant=base | injection. duration = segundos reales."""
    if ATTACK["running"]:
        return {"ok": False, "reason": "ya hay un ataque en curso"}
    if reset_first:
        reset()
    events, geo, bl = SC.build(variant)
    _load_intel(geo, bl)
    ATTACK.update(running=True, variant=variant)
    threading.Thread(target=_attack_worker, args=(events, duration), daemon=True).start()
    return {"ok": True, "variant": variant, "eventos": len(events)}


@app.get("/api/attack/status")
def attack_status():
    return {"running": ATTACK["running"]}


@app.get("/stream")
def stream(mode: str = "auto"):
    """Ejecuta al agente sobre las alertas REALES y transmite lo que hace (SSE)."""
    from agent import run_agent
    def gen():
        for ev in run_agent(mode=mode):
            yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
            time.sleep(0.3)
    return StreamingResponse(gen(), media_type="text/event-stream")
