# CiberGabs SOC Lab

Un **SOC en miniatura** que arranca con un comando, con un **agente de IA** que investiga y responde.

Reproduce una noche en un servidor recién publicado en internet y la recorre por capas:

```
 internet ─► PERÍMETRO ─────────────────────────────► servidor ─► SIEM ─────► agente de IA
             lista negra · geo · fail2ban · WAF        (logs)      (reglas)    (investiga y responde)
```

| Vista | Qué muestra |
|---|---|
| **1 · Logs** | Lo que llega al servidor, con el formato real de Ubuntu (nginx, auth.log) y los "top" de IPs, países, rutas y usuarios |
| **2 · Perímetro** | Cuatro defensas básicas que prendes en vivo y cuánto tráfico frena cada una |
| **3 · SOC + IA** | Las alertas del SIEM y el agente que las correlaciona, contiene y te pide aprobación para lo destructivo |
| **4 · Modelos** | Comparativa de cada corrida: modelo, resultado, tiempo, consultas y tokens |

## Arranque rápido

Necesitas **Git** y **Docker Desktop** abierto.

```bash
git clone https://github.com/GarciaG1/cibergabs-soc-lab.git
cd cibergabs-soc-lab
docker compose up -d
```

Abre **http://localhost:8080**.

> **¿Windows dice "ports are not available"?** Copia `.env.example` como `.env`,
> cambia `SOC_PORT=8080` por `SOC_PORT=5080` (o `9000`) y vuelve a correr `docker compose up -d`.

**Sin Docker** (Python 3.11 o más reciente):

```bash
cd soc
pip install -r requirements.txt
uvicorn app:app --reload --port 8080
```

## Cómo se usa

| Tecla | Hace |
|---|---|
| `1` `2` `3` `4` | Cambia de vista |
| `A` | Lanza el ataque: una noche simulada en 24 segundos |
| `N` | El mismo ataque, con una nota falsa para tu agente (prompt injection) |
| `E` | Ejecuta el agente |
| `R` | Vacía el lab |
| `+` `−` | Tamaño del texto |

Recorrido sugerido: vista 1 + `A` → vista 2, prende las 4 capas + `A` → vista 3 + `E` → aprueba.

## Con IA o sin IA

| | Quién decide |
|---|---|
| **Con `GEMINI_API_KEY`** en `.env` | Un modelo de Gemini elige qué herramientas usar, correlaciona y responde |
| **Sin key** | **Modo reglas**: un analista programado. El lab funciona igual |

La key de Google AI Studio tiene capa gratuita: https://aistudio.google.com/apikey.

En la vista 3 eliges el motor del agente:

| Motor | Para qué |
|---|---|
| **Flash-Lite** | Rápido y económico (el predeterminado, funciona con la capa gratuita) |
| **Flash** | Punto medio. A veces está saturado |
| **Gemini 4 Argon** | El más capaz. De pago y con acceso limitado: si tu key no lo tiene, usa los otros |
| **Reglas** | Sin IA, para comparar |

Cada corrida queda registrada en la vista 4 para comparar modelos con el mismo ataque.

## Taller

[`TALLER.md`](TALLER.md) trae 4 ejercicios sobre este mismo código, con sus soluciones en `taller/soluciones/`:

1. Afinar el perímetro (fail2ban)
2. Tu primera regla del SIEM
3. Una herramienta nueva para el agente
4. Un control humano

La carpeta `soc/` está montada dentro del contenedor: editas, guardas y el lab se recarga solo.

## Estructura

| Archivo | Qué es |
|---|---|
| `soc/scenario.py` | La noche simulada (siempre los mismos datos, para poder ensayar) |
| `soc/app.py` | Perímetro, logs, reglas de detección (SIEM) y API |
| `soc/agent.py` | El agente: herramientas, política de controles y modo reglas |
| `soc/dashboard.html` | El dashboard |
| `docs/wazuh.md` | Cómo pasar a un SIEM real (Wazuh) |

## Seguridad y alcance

- Todas las acciones de respuesta (bloquear IP, aislar host…) son **simuladas**: se registran en el lab y **no tocan tu red**.
- Todo el tráfico es simulado y no sale de tu máquina. Las IPs son de los rangos de documentación (RFC 5737) y no apuntan a nadie real.
- Es material educativo para tu propio entorno.

---

**CiberGabs** · Gabriel García · material del taller *Agentes de IA aplicados a la Ciberseguridad* (lab10).
