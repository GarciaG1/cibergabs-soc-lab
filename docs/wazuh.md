# Nivel 2 (opcional): conectar el agente a **Wazuh** real

El lab base es liviano a propósito. Si quieres un **SIEM de verdad**, aquí está el
camino: levantar Wazuh y apuntar el mismo agente de IA a sus alertas reales.

> **Requisitos:** ~4 GB de RAM libres y unos 20–50 GB de disco. Si tu equipo va
> justo, quédate con el lab ligero: el aprendizaje es el mismo.

## 1. Levantar Wazuh (single-node, oficial)

Wazuh publica su propio despliegue en Docker. Usa **siempre su repositorio oficial**
(las versiones cambian; revisa la rama vigente en su documentación):

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node

# genera los certificados del indexer
docker compose -f generate-indexer-certs.yml run --rm generator

docker compose up -d
```

Cuando termine tendrás:

| Servicio | Dónde | Para qué |
|---|---|---|
| Wazuh **Dashboard** | https://localhost (443) | UI web (usuario/clave por defecto del repo — **cámbialos**) |
| Wazuh **Indexer** | https://localhost:9200 | Donde viven las alertas (`wazuh-alerts-*`) |
| Wazuh **Manager API** | https://localhost:55000 | Inventario de agentes, active response |

Instala un **agente de Wazuh** en una VM o contenedor "víctima" y, si quieres IDS de
red, añade **Suricata**. Luego genera ataques (nmap, hydra) desde otra máquina.

## 2. Que el agente de IA lea las alertas reales

En `soc/agent.py`, sustituye la herramienta `get_alerts` por una que consulte el
**Indexer**. Ejemplo mínimo:

```python
import os, json, requests, urllib3
urllib3.disable_warnings()  # el lab usa certificados autofirmados

WAZUH_URL  = os.environ.get("WAZUH_INDEXER", "https://localhost:9200")
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")

def get_alerts() -> str:
    """Trae las alertas recientes de Wazuh para hacer triage (JSON)."""
    query = {
        "size": 40,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-30m"}}},
            {"range": {"rule.level": {"gte": 5}}},      # ignora ruido de bajo nivel
        ]}},
    }
    r = requests.get(f"{WAZUH_URL}/wazuh-alerts-*/_search",
                     auth=(WAZUH_USER, WAZUH_PASS), json=query,
                     verify=False, timeout=10)
    hits = r.json().get("hits", {}).get("hits", [])
    alerts = [{
        "id": h["_id"][:8],
        "rule": h["_source"]["rule"]["id"],
        "severity": ("critical" if h["_source"]["rule"]["level"] >= 12
                     else "high" if h["_source"]["rule"]["level"] >= 8 else "medium"),
        "message": h["_source"]["rule"]["description"],
        "host": h["_source"].get("agent", {}).get("name"),
        "src_ip": h["_source"].get("data", {}).get("srcip"),
        "user": h["_source"].get("data", {}).get("dstuser"),
    } for h in hits]
    return json.dumps(alerts, ensure_ascii=False)
```

Las demás herramientas (`check_ip_reputation`, `search_events`, `open_incident`…)
siguen igual: el agente no se entera del cambio. **Ese es el punto** — las
herramientas son la frontera.

## 3. Respuesta real (con mucho cuidado)

Wazuh tiene **Active Response**: puede ejecutar de verdad un bloqueo de IP
(`firewall-drop`) en el endpoint. Se dispara por API:

```bash
curl -k -u user:pass -X PUT "https://localhost:55000/active-response?agents_list=001" \
  -H "Content-Type: application/json" \
  -d '{"command":"firewall-drop","arguments":["-","<IP>"]}'
```

> ⚠️ Hazlo **solo en tu laboratorio**. Un agente de IA con permiso de bloquear
> tráfico en producción, sin aprobación humana, es exactamente el *exceso de agencia*
> del que habla la charla. Si lo conectas de verdad: **allowlist de acciones, tope de
> ejecuciones y humano en el loop** para lo destructivo.

## 4. Qué aprendes con este salto

- Que el agente no cambia: cambian **sus herramientas**.
- Que un SIEM real trae **mucho más ruido** — y ahí el triage automático vale oro.
- Que la diferencia entre "IA que analiza" e "IA que actúa" es una decisión de
  **permisos**, no de modelo.
