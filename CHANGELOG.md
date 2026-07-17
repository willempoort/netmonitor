# Changelog

Alle noemenswaardige wijzigingen aan NetMonitor worden hier bijgehouden.

## Versiebeleid

NetMonitor volgt [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR**: breaking changes (incompatibele schema/config-wijzigingen, verwijderde features)
- **MINOR**: nieuwe functionaliteit, backwards compatible (nieuwe detectors, dashboard-features, API-endpoints)
- **PATCH**: alleen bugfixes, geen nieuwe functionaliteit

Het versienummer staat in `version.py` (`__version__`) en wordt getoond in de dashboard-navbar en via `/api/status`.
Bump `version.py` in dezelfde commit als de wijziging, en voeg hieronder een entry toe.

Database schema-versies (`SCHEMA_VERSION` in `database.py`) lopen apart en hoeven niet 1-op-1 met de applicatieversie mee te bewegen — alleen bumpen als de wijziging voor gebruikers/operators zichtbaar of relevant is.

## [2.3.5] - 2026-07-17

### Fixed
- **`install_complete.sh` annuleerde zichzelf stilletjes op elk OS behalve exact Ubuntu 24.04 of Debian 12.** De OS-waarschuwing ("Toch doorgaan?") en de daaropvolgende "Doorgaan met installatie?"-prompt gebruiken allebei `read -n 1`, dat maar 1 teken leest en de Enter-toets (of extra tekens bij bv. "yes") in de inputbuffer laat staan. Zonder read ertussenin werd die restinvoer door de tweede prompt gelezen als lege/foutieve invoer, waardoor de installatie afbrak alsof de gebruiker "N" had geantwoord - ook al werd er twee keer "y" ingetikt. Trof elke niet-expliciet-whitelisted OS-versie (Debian 13, Ubuntu 22.04/26.04, ...). Dezelfde bug zat in de "Keuze (1/2/3)"-prompt van `setup_database()` en in `install_services.sh` (per-service enable-prompts in een lus). Opgelost met een `drain_stdin_line`-helper die na elke `read -n 1` de restbuffer leegt.
- `mcp_server/threat_intel/load_knowledge_base.py` en `sync_service.py` (STAP 7, threat intelligence setup) faalden altijd met `ModuleNotFoundError` voor `dotenv` en `httpx` - deze stonden niet in `requirements.txt`. Toegevoegd (`python-dotenv`, `httpx`).
- `check_os()` herkende alleen Ubuntu 24.04 en Debian 12 als "volledig ondersteund"; elke andere versie (inclusief Debian 13, dat al een eigen fix heeft, en Ubuntu 22.04) kreeg een "niet getest"-waarschuwing. Uitgebreid naar een expliciete lijst (Ubuntu 22.04/24.04/26.04, Debian 12/13).

### Added
- Ubuntu 26.04 LTS geverifieerd als volledig ondersteund: complete installatie (PostgreSQL 18 + TimescaleDB 2.28, NetMonitor Core, MCP Streamable HTTP API, nginx met self-signed TLS) end-to-end getest, geen OS-specifieke code nodig - de packagecloud TimescaleDB-repo en PGDG hebben al packages voor de `resolute`-codename/PG18-combinatie.

## [2.3.4] - 2026-07-17

### Fixed
- TimescaleDB-installatie (`install_complete.sh` STAP 2, en `setup_database.sh`) gebruikte overal `apt-key add` (al jarenlang deprecated, op recente Debian/Ubuntu-releases niet meer beschikbaar) en hardcodede het packagecloud-repo-pad op `/ubuntu/`, ook op Debian. Vervangen door een moderne `signed-by`-keyring en OS-detectie (`$ID` uit `/etc/os-release`) die het juiste ubuntu/debian-pad kiest.
- `setup_database.sh` installeerde altijd `timescaledb-2-postgresql-14`, ongeacht de daadwerkelijk geïnstalleerde PostgreSQL-versie - detecteert nu net als `install_complete.sh` de echte versie na installatie van de PostgreSQL-basispackages.
- `install_complete.sh` gaf bij een mislukte TimescaleDB-package-install (bv. nog geen packages voor een gloednieuwe OS/PG-versie) geen duidelijke foutmelding - toont nu expliciet welke PG-versie/OS-codename niet gevonden werd.

## [2.3.3] - 2026-07-17

### Fixed
- **`install_complete.sh` installeerde de verkeerde MCP-server.** STAP 11 riep het gearchiveerde `setup_http_api.sh` aan en beheerde de niet-bestaande services `netmonitor-mcp`/`netmonitor-mcp-http`, terwijl de daadwerkelijk gegenereerde/actieve service `netmonitor-mcp-streamable` is. Roept nu `mcp_server/setup_streamable_http.sh` aan en beheert de juiste service. Ook een dubbele, foutief-genaamde vroegtijdige service-start in STAP 10 verwijderd.
- Kapotte verwijzingen naar niet-bestaande scripts (`install_mcp_service.sh`, `setup_http_api.sh`, `mcp_server/server.py`) en verkeerde poort (3000 i.p.v. 8000) hersteld in `setup_venv.sh`, `docs/installation/SERVICE_INSTALLATION.md`, `docs/installation/VENV_SETUP.md`, `docs/installation/POSTGRESQL_SETUP.md`, `docs/usage/ADMIN_MANUAL.md`, `docs/deployment/MIGRATION_GUIDE.md`, `mcp_server/OPEN_WEBUI_SETUP.md`, `README.md`.
- Foutieve MCP-tabelnamen (`mcp_tokens`/`mcp_audit_log`) in `docs/usage/ADMIN_MANUAL.md` gecorrigeerd naar de echte tabellen (`mcp_api_tokens`/`mcp_api_token_usage`).

### Changed
- Vier documenten die uitsluitend de oudere `http_server.py`/`netmonitor-mcp`-architectuur beschreven (`mcp_server/README.md`, `mcp_server/HTTP_API_QUICKSTART.md`, `mcp_server/INSTALLATION.md`, `docs/features/MCP_HTTP_API.md`) plus het bijbehorende, nergens meer geïmporteerde `mcp_server/http_server.py` zelf verplaatst naar `archive/mcp_legacy_http_api/` met een duidelijke deprecatie-banner. `mcp_server/README.md` vervangen door een korte, actuele index die naar `STREAMABLE_HTTP_README.md` wijst.
- `docs/INDEX.md` en overige documentatie wijzen nu naar de actuele MCP-documentatie i.p.v. de gearchiveerde bestanden.

## [2.3.2] - 2026-07-17

### Fixed
- Kapotte `nginx-netmonitor-dual.conf`/`nginx-netmonitor.conf`-verwijzingen (bestonden niet) hersteld naar `nginx-netmonitor.conf.example` in nog vijf documentatiebestanden: `docs/installation/NGINX_SETUP.md`, `docs/deployment/KIOSK-DEPLOYMENT.md`, `docs/installation/COMPLETE_INSTALLATION.md`, `docs/features/DETECTION_FEATURES.md`, `docs/installation/GUNICORN_SETUP.md`.
- `docs/installation/NGINX_SETUP.md` beschreef in de service-mapping en troubleshooting-secties nog de oudere `netmonitor-mcp-http.service`/`http_server.py`-architectuur; gelijkgetrokken naar `netmonitor-mcp-streamable.service`/`streamable_http_server.py` (wat daadwerkelijk draait).

## [2.3.1] - 2026-07-17

### Fixed
- `install_complete.sh` verwees bij de nginx-stap naar het niet-bestaande `nginx-netmonitor.conf`, waardoor die stap altijd faalde. Gecorrigeerd naar `nginx-netmonitor.conf.example` (het enige, actuele template - bevat zowel dashboard- als MCP-routing).
- `NGINX_TEMPLATES.md` beschreef een `nginx-netmonitor-dual.conf` die nooit heeft bestaan, en omschreef het wél bestaande template ten onrechte als "geen MCP". Herschreven naar de werkelijke situatie.
- `mcp_server/setup_streamable_http.sh` detecteert nu (stap 5) of nginx het dashboard al serveert maar de `/mcp`-routing mist, en verwijst dan naar het actuele template - relevant als je MCP later alsnog activeert op een instantie die dit initieel oversloeg.

## [2.3.0] - 2026-07-17

### Added
- "Bevestigen"- en "Toevoegen aan whitelist"-knoppen per alert in de threat-type-detailweergave (voorheen alleen beschikbaar via de alert-feed modal).

## [2.2.0] - 2026-07-17

### Security
- Interne schrijf-endpoints die de MCP-server aanroept (`/api/whitelist`, `/api/alerts/<id>/acknowledge`) vertrouwden `request.remote_addr` zonder `ProxyFix`, waardoor achter nginx *elke* request (ook echt externe, ongeauthenticeerde bezoekers) als "lokaal" werd gezien. `ProxyFix` toegevoegd (vertrouwt exact 1 hop) en nieuwe `local_or_role_required`-decorator die de bestaande admin/operator-rolcheck voor externe requests intact houdt en alleen genuine localhost-aanroepen (MCP-server) vrijstelt.

### Added
- `severity`-filter (CRITICAL/HIGH/MEDIUM/LOW/INFO, niet hoofdlettergevoelig) op de `get_threat_detections` MCP-tool, naast de bestaande `get_recent_threats`.
- Nieuwe MCP-tool `acknowledge_alert` en een "Bevestigen"-knop in de dashboard alert-detail modal (bevestigt alle gegroepeerde meldingen in één keer).

### Fixed
- Ollama-provider in netmonitor-chat ondersteunde geen `max_tokens`, verwerkte `tool_calls.arguments` verkeerd (Ollama levert een dict, geen gestreamde string) en toonde bij HTTP-fouten alleen een generieke statuscode i.p.v. Ollama's eigen foutmelding.
- Strikte severity-`enum` in tool-schema's veroorzaakte een onnodige retry-ronde bij afwijkend hoofdlettergebruik (bv. "Critical" i.p.v. "CRITICAL"); nu een vrij veld met server-side normalisatie.
- Modellen gebruikten de severity-parameter niet bij vragen naar een specifiek ernstniveau door ontbrekende tool-guidance in de system prompt.
- netmonitor-chat gaf soms stilzwijgend geen antwoord wanneer het model na een tool-aanroep niets teruggaf (bv. bepaalde Qwen3.5 MTP-varianten).

## [2.1.0] - 2026-07-14

### Fixed
- AbuseIPDB/MISP/OTX threat-intel lookups cachten alleen positieve treffers, waardoor elk "schoon" IP bij elke alert opnieuw een live API-call veroorzaakte. Dit putte de AbuseIPDB dagelijkse rate limit (1000/dag) onopgemerkt uit, omdat deze route niet naar de `abuseipdb_api_stats` tabel schreef die het dashboard-overzicht voedt. Negatieve resultaten worden nu ook gecached.
- `query_suspicious_only` config-optie (bestond al in config.yaml, deed niets) geïmplementeerd: private/loopback/reserved IP's worden nu overgeslagen bij AbuseIPDB-lookups.
- IP-reputatiepaneel in de "toevoegen aan whitelist"-modal gaf een 404 wanneer het alert-IP een CIDR-suffix bevatte (bv. `10.100.0.2/32`).
- Cache-busting versieparameter van `dashboard.js` niet verhoogd na wijzigingen, waardoor nginx' 30-dagen-immutable cache op `/static/` verouderde JS bleef serveren.

### Added
- "Toevoegen aan whitelist"-knop op alert-detail modal, met voorgevulde bron/doel-IP en poort.
- IP-reputatiepaneel (land, ASN/organisatie, AbuseIPDB score, Tor/VPN/proxy/datacenter-tags) via nieuwe `/api/ip-info/<ip>` endpoint, om te beoordelen of een IP te vertrouwen is vóór whitelisting.
- Versienummer zichtbaar in dashboard-navbar en `/api/status`.
