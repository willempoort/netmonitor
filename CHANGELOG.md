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
