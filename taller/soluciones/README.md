# Soluciones del taller

Intenta primero sin verlas.

| Ejercicio | Solución |
|---|---|
| 1 · Afina el perímetro | En `soc/app.py`: `F2B_MAXRETRY = 2`. El atacante falla 2 veces y queda baneado antes de entrar. **Regrésalo a `5`** para los siguientes ejercicios. |
| 2 · Regla del SIEM | [`ejercicio2_regla_siem.py`](ejercicio2_regla_siem.py). Los huecos: `CUENTAS_DE_SERVICIO`, `"password"`, `"high"`. |
| 3 · Herramienta del agente | [`ejercicio3_herramienta.py`](ejercicio3_herramienta.py). Los huecos: una descripción clara de la herramienta y `user`. No olvides agregarla a `BASE_TOOLS`. |
| 4 · Control humano | En `soc/agent.py`: `NEEDS_APPROVAL = {"isolate_host", "disable_account", "revoke_sessions"}` |
