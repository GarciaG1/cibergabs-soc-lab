# Taller · Construye tu SOC con IA

Vas a levantar un SOC en tu máquina y a construirle **4 piezas** sobre el código real.
Cada cambio se ve de inmediato en el dashboard: guardas el archivo y el lab se recarga solo.

| # | Archivo | Construyes | Lo que vas a ver |
|---|---|---|---|
| 1 | `soc/app.py` | Afinar el perímetro (fail2ban) | El embudo cambia… y un dilema |
| 2 | `soc/app.py` | Tu primera regla del SIEM | Una alerta nueva que delata al atacante |
| 3 | `soc/agent.py` | Una herramienta nueva para el agente | El agente la usa y razona con ella |
| 4 | `soc/agent.py` | Un control humano | Otro botón **Aprobar** |

---

## 0 · Levanta tu lab (5 min)

Necesitas **Git**, **Docker Desktop** abierto y un editor (VS Code, por ejemplo).

```bash
git clone https://github.com/GarciaG1/cibergabs-soc-lab.git
cd cibergabs-soc-lab
docker compose up -d
```

Abre **http://localhost:8080**.

> **Windows dice "ports are not available"?** Windows a veces reserva ese puerto.
> Copia `.env.example` como `.env`, cambia `SOC_PORT=8080` por `SOC_PORT=5080`
> (o `9000`), vuelve a correr `docker compose up -d` y abre ese puerto.

**Sin Docker** (Python 3.11 o más reciente):

```bash
cd cibergabs-soc-lab/soc
pip install -r requirements.txt
uvicorn app:app --reload --port 8080
```

### Cómo se usa el dashboard

| Tecla | Hace |
|---|---|
| `1` `2` `3` | Cambia de vista: **Logs** · **Perímetro** · **SOC + IA** |
| `A` | Lanza el ataque (una noche simulada, dura 24 segundos) |
| `N` | El mismo ataque, pero el atacante deja una nota falsa para tu IA |
| `E` | Ejecuta el agente |
| `R` | Vacía el lab |

**Antes de empezar los ejercicios:** ve a la vista `2`, prende las **4 capas** y lanza el ataque (`A`).
En la vista `3` deberías ver **7 alertas**. Esa es tu línea base.

> Después de **cada** cambio en el código, el servidor se reinicia y el lab queda vacío:
> vuelve a prender las capas (vista 2) y lanza el ataque otra vez.

---

## Ejercicio 1 · Afina el perímetro (5 min)

**La idea.** fail2ban banea una IP después de `N` contraseñas fallidas. ¿Y si fuéramos más estrictos?

**Dónde.** `soc/app.py`, la línea `F2B_MAXRETRY = 5`.

**Cambia** el `5` por `2`. Guarda → vista 2, prende las capas → `A`.

**Comprueba.** En la vista 2, el embudo deja pasar **menos tráfico**. En la vista 3, la cadena del atacante
queda **apagada**: falló dos veces y fail2ban lo sacó antes de que entrara.

**Para pensar.**
- ¿Ya ganamos? ¿Qué pasa con tu compañero que se equivoca **dos veces** de contraseña?
- ¿Y si el atacante hubiera acertado **a la primera**?

**Regrésalo a `5`** antes de seguir: los siguientes ejercicios necesitan que el atacante entre.

---

## Ejercicio 2 · Tu primera regla del SIEM (8 min)

**La idea.** Las cuentas de servicio (`deploy`, `backup`, `ci`) las usan las máquinas, no las personas:
entran siempre con **llave SSH** desde su servidor. Si una de ellas entra con **contraseña**, alguien se la robó.

**Dónde.** `soc/app.py`, dentro de la función `detect()`, busca el comentario `TALLER · Ejercicio 2`.

**Escribe** (completa los `____`, respeta la sangría de 4 espacios):

```python
    # R13 · Una cuenta de servicio inició sesión con contraseña
    CUENTAS_DE_SERVICIO = {"deploy", "backup", "ci"}
    if et == "ssh_auth_success" and ev.get("user") in ____ \
            and ev.get("method_auth") == "____":
        add_alert("R13-cuenta-servicio", "____",
                  f"La cuenta de servicio '{ev.get('user')}' inició sesión con contraseña desde {ip}", ev)
```

Pistas: ¿en qué conjunto buscas al usuario? ¿Cuál es el método que *no* debería usar? ¿Qué tan grave es? (`low`, `medium`, `high`)

**Comprueba.** Guarda → vista 2, prende las capas → `A` → vista 3.
Ahora hay **8 alertas**, y una nueva: **R13-cuenta-servicio**.

**Para pensar.** El atacante no tenía reportes en ninguna lista negra y no hizo fuerza bruta.
¿Por qué esta regla sí lo encontró?

---

## Ejercicio 3 · Una herramienta nueva para el agente (8 min)

**La idea.** El agente decide qué herramientas usar **leyendo su descripción** (el texto entre `"""`).
Le vas a dar una nueva: consultar el directorio de cuentas de la empresa (`DIRECTORIO`, ya está en el archivo).

**Dónde.** `soc/agent.py`, busca el comentario `TALLER · Ejercicio 3`.

**Escribe** (completa los `____`):

```python
def lookup_user(user: str) -> str:
    """____"""
    return json.dumps(DIRECTORIO.get(____, {"user": user, "existe": False}), ensure_ascii=False)
```

- En la descripción, explica **para qué sirve** la herramienta. Es lo único que el modelo lee para decidir si usarla.
- Luego agrégala a la lista `BASE_TOOLS`, justo abajo: `..., close_alert, lookup_user]`

**Comprueba.** Guarda → capas → `A` → vista 3 → `E`. En la consola del agente aparece
`lookup_user deploy`, seguida del razonamiento: *"deploy es una cuenta de servicio: nunca debería iniciar sesión con contraseña"*.

> Con `GEMINI_API_KEY` el que decide usarla es el modelo. Sin key, el modo reglas también la usa.

**Para pensar.** Si escribes una descripción vaga o engañosa, ¿qué crees que hará el modelo?

---

## Ejercicio 4 · Un control humano (4 min)

**La idea.** Hay acciones que el agente puede hacer solo (bloquear una IP es reversible) y otras que
deberían pasar por una persona. Hoy, revocar sesiones lo hace sin preguntar.

**Dónde.** `soc/agent.py`, la línea `NEEDS_APPROVAL = {"isolate_host", "disable_account"}`.

**Agrega** `"____"` al conjunto para que **revocar sesiones** también requiera aprobación.

**Comprueba.** Guarda → capas → `A` → vista 3 → `E`. Ahora hay **3** botones **Aprobar** en el incidente.

**Para pensar.** El control vive en el **código**, no en las instrucciones del modelo.
¿Por qué eso importa cuando alguien intenta engañar al agente? (Pruébalo: apaga los **Controles** en la vista 3 y usa `N`.)

---

## Si algo falla

| Problema | Solución |
|---|---|
| El dashboard no carga | `docker compose ps` debe decir *running*. Si no: `docker compose logs soc` |
| Guardé y no pasa nada | Revisa `docker compose logs soc`: un error de sangría o un `____` sin llenar detiene el servidor |
| `IndentationError` | Tu código debe tener la misma sangría que las reglas de arriba (4 espacios) |
| Puerto ocupado o reservado | Cambia `SOC_PORT` en `.env` (ver paso 0) |

Las soluciones completas están en `taller/soluciones/`. Intenta primero sin verlas.
