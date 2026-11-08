# Code-audit: projectcontext NetMonitor

Gelezen door de globale `code-audit` skill (`~/.claude/skills/code-audit/`). Hier staat wat specifiek is voor deze repo.

## Uitsluitingen en commando's
- `archive/` is een bewust bewaarde referentie. Niet auditen en niet wijzigen.
- Tests: `python3 -m pytest tests/unit -q -p no:cacheprovider` (gebruik altijd `python3`, niet `python`).
- Bekende nulmeting: 5 errors in `tests/unit/test_web_dashboard.py::TestAPIEndpoints`, door een probleem met de `flask_login` mock. Die bestonden al.
- Comments en docstrings zijn vaak Nederlands. Laat dat zo.
- Versie en changelog: bump `version.py` en voeg een entry toe aan `CHANGELOG.md` als een wijziging zichtbaar is voor gebruikers of operators (security-fixes meestal wel, alleen dode code verwijderen meestal niet).

## Aanvalsoppervlak
- De server heeft geen publiek IP (`10.100.0.2`, gateway `10.100.0.254`). In de nginx-logs komen alleen clients uit `10.100.0.0/24` voor: de sensors `.57/.91/.110/.111` en de beheer-clients `.58/.70`. "Anoniem" betekent hier dus: iedereen op het interne netwerk of de VPN.
- nginx is het enige wat luistert op 80/443. De live config staat in `/etc/nginx/sites-enabled/soc-dual.conf`, het voorbeeld in `nginx-netmonitor.conf.example`. De sensor-zijde endpoints zijn daar beperkt tot de 4 sensor-IP's (audit K1). Een nieuwe sensor betekent dus ook een nieuwe `allow`-regel.
- `sensor_auth.allow_missing_token` in `config.yaml` staat sinds 2026-11-08 **tijdelijk aan**, omdat de sensors nog geen token sturen. Rapporteer dit als open punt zolang het aan staat.
- Dashboard: gunicorn op `127.0.0.1:8080`. MCP-server: `127.0.0.1:8000`. PostgreSQL: alleen localhost.
- `web_dashboard.py` gebruikt `ProxyFix(x_for=1)`. `is_local_request()` / `local_or_*_required` zijn alleen veilig zolang elke nginx-location naar het dashboard `X-Forwarded-For` zet.
- Auth-decorators: `login_required`, `require_role`, `require_sensor_token(perm)`, `require_sensor_token_or_login`, `local_or_login_required`, `local_or_role_required`.
- Sensors draaien als root (`services/netmonitor-sensor.service.template`) en voeren commando's van de server uit (`sensor_client.py`, `command_type`).

## Entry points en dynamische dispatch
- Flask-routes en `@socketio.on` in `web_dashboard.py`. Frontend-aanroepen staan in `web/static/js/*.js`.
- MCP: `streamable_http_server.py` en `openwebui_rest_wrapper.py` gebruiken `getattr(self.tools, name)`. Elke tool-methode in `mcp_server/shared_tools.py` is dus in gebruik als de naam in de tool-definities staat.
- systemd-templates in `services/*.template`, gunicorn-hooks in `gunicorn_config.py`.

## Bekende duplicaatparen
- `detector.py` ↔ `behavior_detector.py` ↔ `baseline_detector.py`
- `is_internal_ip` in 6 bestanden (baseline, behavior, metrics, sensor_client, device_discovery, risk_scoring)
- `database.py` ↔ `mcp_server/database_client.py` (te groot voor een opruimronde, apart project)
- `abuseipdb_client.py` ↔ `integrations/threat_intel/abuseipdb_source.py`
- `web_dashboard.py`: paren `api_*` ↔ `api_internal_*`
- **Bewuste standalone-kopieën, niet samenvoegen:** `mcp_server/mcp_streamable_http_bridge.py` ↔ `mcp_server/clients/*/` (moeten byte-identiek blijven)

## Secrets
- Live secrets staan in `/opt/netmonitor/.env`. Dat bestand staat niet in git.
- `env_settings.txt` en `env_new_settings.txt` stonden tot 2026-11-08 met echte waarden in git (audit K2).
