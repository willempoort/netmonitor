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
