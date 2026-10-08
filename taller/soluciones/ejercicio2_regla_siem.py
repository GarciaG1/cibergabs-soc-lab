# Ejercicio 2 · Tu primera regla del SIEM
# Pega esto en soc/app.py, dentro de detect(), debajo de "TALLER · Ejercicio 2".
# (respeta la sangría: 4 espacios, igual que las otras reglas)

    # R13 · Una cuenta de servicio inició sesión con contraseña.
    # Las cuentas de servicio (deploy, backup, ci…) solo entran con llave SSH desde
    # sus servidores. Si una entra con contraseña, alguien robó esa contraseña.
    CUENTAS_DE_SERVICIO = {"deploy", "backup", "ci"}
    if et == "ssh_auth_success" and ev.get("user") in CUENTAS_DE_SERVICIO \
            and ev.get("method_auth") == "password":
        add_alert("R13-cuenta-servicio", "high",
                  f"La cuenta de servicio '{ev.get('user')}' inició sesión con contraseña desde {ip}", ev)
