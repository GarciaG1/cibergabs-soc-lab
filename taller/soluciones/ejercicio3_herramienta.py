# Ejercicio 3 · Una herramienta nueva para el agente
# Pega la función en soc/agent.py, debajo de "TALLER · Ejercicio 3",
# y luego agrega lookup_user a la lista BASE_TOOLS (justo abajo).

def lookup_user(user: str) -> str:
    """Consulta en el directorio de la empresa qué tipo de cuenta es y cómo debería iniciar sesión.

    Args:
        user: nombre de la cuenta, p. ej. deploy
    """
    return json.dumps(DIRECTORIO.get(user, {"user": user, "existe": False}), ensure_ascii=False)


# y en la lista:
# BASE_TOOLS = [get_alerts, check_ip_reputation, lookup_ioc, search_events, open_incident,
#               block_ip, isolate_host, disable_account, revoke_sessions, close_alert,
#               lookup_user]
