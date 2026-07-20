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

## [2.5.1] - 2026-07-20

### Fixed
- **"Alle Alerts"-venster gaf op servers met veel `top_talkers`-data een lege lijst of een timeout-fout ("Unexpected token '<'").** `search_alerts()` doet per alert-rij een LATERAL-lookup naar `top_talkers` om de source/destination-hostname te vinden, maar had geen index op `(ip_address, timestamp)`. Zodra `top_talkers` groot genoeg werd, moest TimescaleDB alle chunks scannen per lookup, wat de query minutenlang liet duren, de eventlet gunicorn-worker deed timeouten (`WORKER TIMEOUT`) en resulteerde in een nginx 504 (HTML-response i.p.v. JSON) of - erger - een stilzwijgend leeg resultaat doordat `search_alerts()` alle fouten ving en `{'alerts': [], 'total_count': 0}` teruggaf. Nieuwe index `idx_top_talkers_ip_timestamp` (schema v32) lost de traagheid op; `search_alerts()` geeft fouten nu door in plaats van ze te maskeren als "geen resultaten".

## [2.5.0] - 2026-07-20

### Added
- **"Alle Alerts"-venster: volledig doorzoekbaar alertoverzicht.** Nieuwe knop in de navbar opent een full-screen modal met alle alerts (niet beperkt tot de laatste 20 zoals de dashboardwidget), met filters op severity, bevestigd/onbevestigd, threat type (autocomplete uit alle 44 ooit voorgekomen typen), IP/hostname en periode, plus paginering en per-rij bevestigen/whitelisten. Backend: `db.search_alerts()` met dynamische filters + `total_count`, nieuwe endpoints `/api/alerts/search` en `/api/alerts/threat_types`, en nieuwe indexes `idx_alerts_acknowledged_timestamp`/`idx_alerts_severity` (schema v31) voor performante filtering op de volledige tabel.

### Fixed
- **Bevestigde alerts bleven zichtbaar in "Recent Alerts".** De widget haalde alerts op zonder op `acknowledged` te filteren, dus bevestigen veranderde niets aan de lijst totdat het item toevallig uit de laatste-20-vensterperiode viel. `get_recent_alerts()` sluit bevestigde alerts nu uit voor deze widget (andere aanroepers ongewijzigd), en bevestigen in de UI verwijdert het item direct uit de feed.
- **Labels en placeholder-tekst onleesbaar in het "Alle Alerts"-venster.** De bestaande contrastfix voor `.text-muted` gold alleen binnen `.card`-elementen, niet binnen modals; toegevoegd voor `#allAlertsModal` plus een algemene fix voor placeholder-tekst in donkere invoervelden.
- **Threat type-filter toonde maar 4 opties.** De lijst kwam uit de 24-uursstatistiek (top 10 op basis van recente counts) i.p.v. alle ooit voorgekomen typen; nu gevuld via het nieuwe `/api/alerts/threat_types`-endpoint.

## [2.4.3] - 2026-07-19

### Fixed
- **Shelly Gen2 (Plus/Pro) bleef "IoT Sensor" krijgen i.p.v. "Smart Switch/Dimmer".** Gen1-Shelly's adverteren hun model in de mDNS service-instancenaam (`shellydimmer-…`), maar Gen2 adverteert alleen generieke services (`_http._tcp`, `_shelly._tcp`) en zet het model in de mDNS-hostnaam (`ShellyPro2-….local`) - waar de fingerprint-interpretatie niet naar keek. De generieke shelly-hint won daardoor (template-default "IoT Sensor") van het specifiekere hostname-bewijs, dat door de fingerprint-voorrang nooit meer aan bod kwam. Twee fixes: de geprobede mDNS-hostnaam telt nu mee als model-bewijs (met Shelly-modelprefixen in de keyword-tabel), en generieker: als de fingerprint alleen de *categorie* identificeert terwijl de hostname-heuristiek hetzelfde type met een specifiekere template aanwijst, wordt die template overgenomen.

## [2.4.2] - 2026-07-19

### Fixed
- **"Fingerprint Scan"-knop deed niets in browsers met gecachte JavaScript.** v2.4.0 voegde `runFingerprintScan()` toe aan `device-classification.js` maar de cache-buster in dashboard.html bleef op `?v=11` staan - browsers die het dashboard eerder bezochten hielden de oude JS vast, waardoor de nieuwe knop een ReferenceError gaf en pas na een harde refresh werkte. Cache-buster opgehoogd naar `?v=12`.

## [2.4.1] - 2026-07-19

### Fixed
- **Shelly's kregen de generieke "IoT Sensor"-template ondanks dat de fingerprint het exacte model bevatte.** De mDNS service-instancenaam (bv. `shellydimmer-D3E7B4`, `shelly1-E098068D1508`) en de hostname-prefixen `shsw-`/`shdm-` onderscheiden schakel-/dimmodules van andere IoT-apparaten; die mappen nu naar de specifiekere template "Smart Switch/Dimmer" (en `shellyplug`/`shplg-` naar "Smart Plug"). Overige Shelly's houden de categorie-default. Op installaties zonder die templates valt de toewijzing netjes terug op alleen classificatie-metadata.

## [2.4.0] - 2026-07-19

### Added
- **Device fingerprinting: identiteitsbewijs voor classificatie (`device_fingerprinter.py`).** De ML-classifier beoordeelt alleen *gedrag* (verkeerspatronen) en duwde met een scheve trainingsset (18× iot_sensor vs. 3× mobile) zelfs een tablet met 95% zekerheid in "IoT Sensor". Er zijn nu twee nieuwe, hoger geprioriteerde bewijsbronnen:
  - **Passief (altijd aan): hostname-heuristiek.** Hostnames benoemen het apparaat vaak letterlijk ("iPhone…", "Tab-A8-van-Willem", "MacBook", "sonos…", "shsw-…"); een patroontabel vertaalt dit naar type + specifieke template, voor álle apparaattypen i.p.v. alleen de bestaande mobile-verfijning.
  - **Actief (LAN-only, config-gated `fingerprinting:`): lichte polls.** mDNS-query (UDP 5353: .local-hostname, service-enumeratie, Apple `model=`), SSDP M-SEARCH + description-XML (friendlyName/modelName/manufacturer), NetBIOS node status (Windows-naam/werkgroep), LLMNR reverse lookup, en SNMP v2c sysDescr/sysName (minimale eigen BER-implementatie, geen extra dependency). Alles kleine UDP-pakketjes met korte timeouts; geen port scans. Ruw bewijs wordt opgeslagen in `devices.fingerprint` (JSONB, schema v30) en pas bij classificatie geïnterpreteerd, zodat verbeterde regels geen re-scan vereisen.
  - **Prioriteit: fingerprint > hostname > ML-model > vendor-hint.** Bij overeenstemming krijgt het ML-resultaat een confidence-boost en de specifiekere template; bij conflict wint identiteitsbewijs (met het ML-oordeel in de reasoning).
  - **Dashboard-knop "Fingerprint Scan"** (naast Train Model): actieve scan + aansluitende herclassificatie als achtergrondtaak; ook via `/api/ml/fingerprint-scan` en `/api/internal/ml/fingerprint-scan`. De scheduled ML-cyclus ververst het bewijs voortaan automatisch vóór de auto-classificatie.
  - **Nieuwe categorie `smartwatch` + builtin template "Smartwatch"** (herkend via hostname of mDNS-model).

## [2.3.18] - 2026-07-19

### Fixed
- **"Run ML Classification" (en scheduled training) kon een gunicorn-worker laten killen, waarna de knop permanent "already running" teruggaf en classificatievoorstellen nooit meer bijgewerkt werden.** Drie samenhangende oorzaken verholpen:
  - Onder `eventlet.monkey_patch()` zijn de "background threads" voor trainen/classificeren green threads: CPU-bound sklearn-werk blokkeerde de complete event loop van de worker, die daardoor zijn gunicorn-heartbeat miste en na 30s met SIGKILL werd afgeschoten (`WORKER TIMEOUT` in dashboard_error.log). Het ML-werk draait nu via `eventlet.tpool` in een echte OS-thread (`run_blocking()` in ml_classifier.py), zodat de event loop blijft reageren. Buiten eventlet (engine/CLI) is het een gewone call. Daarnaast traint de RandomForest nu met `n_jobs=1`: het model hergebruikt zijn `n_jobs` bij `predict_proba()`, en joblib-parallellisme op monkey-gepatchte locks in green threads kan deadlocken (bij dit datavolume levert parallellisme toch niets op).
  - Een door SIGKILL gestorven worker kon `background_task_status` nooit meer bijwerken, dus de taak bleef eeuwig op `running` staan en `try_start_background_task()` weigerde elke volgende run. Een `running`-rij ouder dan 10 minuten geldt nu als verweesd: hij is opnieuw claimbaar en de status-API rapporteert hem als `error` in plaats van een eeuwige spinner.
  - Elke van de 4 gunicorn-workers startte zijn eigen scheduled-training-thread, waardoor 5 minuten na elke (her)start 4 trainingen tegelijk de CPU verzadigden en workers elkaar in een permanente kill/reboot-cyclus hielden (~elke 5,5 min een `WORKER TIMEOUT`). De scheduled cycle claimt nu eerst het DB-slot `ml_scheduled_train`; alleen de winnaar draait, de rest slaat de cyclus over.

### Notes
- De changelog-entries en `version.py`-bumps voor 2.3.12 t/m 2.3.17 ontbreken: die wijzigingen zitten alleen in de commit-messages (zie `git log`). Deze release herstelt de nummering.

## [2.3.11] - 2026-07-18

### Fixed
- **Template→trainingslabel-mapping labelde "File Server (NAS)" als `server` i.p.v. `nas`.** `_infer_label_from_template()` matcht op substrings in dict-volgorde, en het generieke `'server'` stond vóór het specifiekere `'file server'`/`'nas'` - een handmatig als NAS geclassificeerde Synology ging dus als verkeerd label de ML-training in. Matching gebeurt nu longest-key-first zodat specifieke templatenamen altijd winnen van generieke substrings.
- **De ingebouwde templates "Smart Plug", "Smart Light" en "Home Automation Hub" mapten naar geen enkele trainingscategorie** - devices met die templates (bv. Tuya smart plugs) droegen niets bij aan de trainingsdiversiteit. Toegevoegd als `iot_sensor`, plus `'power switch'` → `iot_sensor` zodat custom relais-templates ("iOT smart power switch") niet per ongeluk als netwerk-switch (`network_device`) gelabeld worden.

## [2.3.10] - 2026-07-18

### Fixed
- **Device-classificatievoorstellen waren onzichtbaar in het dashboard, ook voor devices met learning status "Ready".** De classifier schreef wel `classification_method`/`classification_confidence` naar de database (sinds 2.3.6), maar het voorgestelde *type* zelf werd weggegooid: een template wordt pas echt toegewezen bij confidence ≥ 0.7, terwijl vendor-hints (de enige methode die kan vuren zolang er geen ML-model getraind is) per ontwerp op 0.6 gecapt zijn - en de UI toonde een voorstel uitsluitend via een toegewezen template. Gevolg: 19 devices hadden een berekend voorstel (Sonos → Smart Speaker, Espressif → IoT Sensor, Synology → NAS, ...) dat nergens te zien was; de devices-tabel toonde gewoon "Unclassified". Nieuw: `devices.suggested_template_id` (schema v23) bewaart het voorstel onder de auto-assign-drempel; de devices-tabel toont nu een "Suggested: <template> (60%)"-badge met een ✓-knop om het voorstel te accepteren. Bij (handmatige of automatische) template-toewijzing wordt het voorstel gewist.

### Notes
- Het ML-model zelf traint (bewust, zie 2.3.7) nog niet op dit netwerk: er zijn nu 2 categorieën met 3+ voorbeelden (iot_sensor 11, smart_speaker 6; nas en network_device elk 1), minimaal 4 nodig. Dit lost zichzelf op naarmate voorstellen geaccepteerd/templates handmatig toegewezen worden - elke bevestiging telt als trainingslabel.

## [2.3.9] - 2026-07-18

### Fixed
- **`install_complete.sh` stelde altijd `eth0` en `192.168.1.0/24` voor**, ongeacht de daadwerkelijke server-interface/subnet - op een VM met alleen `lo`/`ens18` moest je dus altijd handmatig overtypen. Het script detecteert nu de interface met de default route (valt terug op de eerste UP niet-`lo`-interface) en leidt de subnet-CIDR af van het IPv4-adres op de gekozen interface; beide blijven overschrijfbaar en een bestaande `.env`-waarde wint nog steeds.
- **2FA werd twee keer gevraagd tijdens installatie**, en de eerste vraag ("Verplicht 2FA voor dashboard login?", schreef naar `REQUIRE_2FA` in `.env`) deed niets - die env var wordt nergens in de Python-code gelezen. Het enige werkende 2FA-aanbod zit in `setup_admin_user.py` (STAP 9); de dode prompt in `prompt_config()` is verwijderd.
- **Nginx-keuze had geen invloed op dashboard/MCP bind-adres of op de getoonde URL's.** Met nginx als reverse proxy hoeven Flask/uvicorn niet zelf op `0.0.0.0` te luisteren - de Nginx-vraag wordt nu vóór de Dashboard/MCP-host-vragen gesteld en stuurt de voorgestelde default (`127.0.0.1` met nginx, anders `0.0.0.0`, nog steeds overschrijfbaar). De "Volgende stappen"-URL's (`install_complete.sh` summary en `post_install.sh`) tonen nu `https://<domain-of-server-ip>` zodra nginx geconfigureerd is, i.p.v. altijd `http://localhost:8080`.
- **`download_geoip_db.sh` toonde alleen een handmatige restart-instructie** ("Restart netmonitor service: sudo systemctl restart netmonitor") in plaats van het zelf te doen. Herstart de service nu automatisch wanneer die al actief is (bv. tijdens/na installatie); toont de handmatige instructie alleen nog als de service nog niet bestaat/draait.
- **"Duplicate MAC Addresses" werd bij (bijna) elke installatie/herstart meteen gemeld.** De achtergrondtaak die dubbele MAC-rijen opruimt (ontstaan door DHCP-churn tijdens de eerste netwerk-sweep, zie `cleanup_duplicate_mac_devices()`) draaide pas na 30 minuten (elke 30e iteratie van de 60s-loop). `device_discovery.py` draait nu een eenmalige vroege opruimronde 2 minuten na startup, zodat de melding niet bij elke restart tot 30 minuten blijft staan.

## [2.3.8] - 2026-07-17

### Fixed
- **Het subnet-broadcast-adres (bv. `10.100.0.255`) werd getrackt als een normaal "apparaat".** `internal_networks` in `config.yaml.example` bevat alleen de brede RFC1918-supernetten (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); `_is_broadcast_or_multicast()` in `device_discovery.py` herkent een IP alleen als broadcast wanneer het exact het broadcast-adres van een van de geconfigureerde netwerken is - en dat is voor een `/8` bijvoorbeeld `X.255.255.255`, niet het broadcast-adres van het daadwerkelijke `/24`-subnet. De installatieprompt "Jouw interne netwerk CIDR" verzamelt precies de benodigde precieze CIDR, maar die waarde werd alleen naar `.env` geschreven en nooit toegepast op `internal_networks` in `config.yaml` - trof dus elke installatie, ongeacht het ingevoerde antwoord. `install_complete.sh` voegt het opgegeven netwerk nu toe aan `internal_networks` in `config.yaml` (idempotent, naast de bestaande brede defaults).

## [2.3.7] - 2026-07-17

### Fixed
- **ML device-classificatie wees niet-IoT devices met hoge (fout) confidence toe aan "Smart Speaker"/"IoT Sensor".** Nadat het model voor het eerst voldoende data had om te trainen, bleken maar 2 categorieën genoeg voorbeelden te hebben (smart_speaker, iot_sensor). Een RandomForestClassifier kan alleen kiezen uit de klassen waarop hij getraind is - hij heeft geen "geen van deze" optie - waardoor onder andere de SOC-server en een MacBook Air als "Smart Speaker" (95% confidence) en een UniFi-controller en Android-tablet als "IoT Sensor" (80-96% confidence) werden geclassificeerd en automatisch die template kregen toegewezen. `train()` vereist nu minimaal 4 categorieën met voldoende voorbeelden (was 2) voordat een model bruikbaar wordt geacht. Het al opgeslagen 2-klassen-model is verwijderd zodat het niet na herstart opnieuw geladen wordt.
- Template-namen "UniFi Controller", "Network Device" en enkele andere server-templates (DNS/DHCP/PBX/Remote Desktop/Samba Server) werden niet herkend door de template→categorie-mapping die trainingslabels aflevert voor `train()` - handmatig toegewezen templates met die namen droegen daardoor niets bij aan het uitbreiden van de trainingsdiversiteit. Mapping aangevuld.

## [2.3.6] - 2026-07-17

### Fixed
- **`get_device_by_ip()` (database.py en mcp_server/database_client.py) kon een verkeerde/inactieve rij teruggeven** wanneer er duplicaat-rijen voor hetzelfde IP bestonden: geen `is_active`-filter en geen `ORDER BY`, dus Postgres gaf een arbitraire rij terug. Concreet gevolg: de "confirm template"-knop in het dashboard meldde succes maar paste de wijziging toe op een verborgen, gedeactiveerde duplicaat-rij, terwijl de zichtbare (actieve) rij ongewijzigd bleef. Trof elke lookup-by-IP-actie (template toewijzen, learned behavior opslaan, threat-detectie, risk scoring, MCP-tools). Nu gefilterd op `is_active = TRUE` met deterministische sortering (`last_seen DESC, id DESC`).
- **`register_device()` kon duplicaat-devicerijen aanmaken** wanneer het ooit met `sensor_id=None` werd aangeroepen: de MAC-based dedup-lookup gebruikte `sensor_id = %s`, en in SQL matcht `NULL = NULL` nooit, dus de lookup vond het bestaande device niet en er werd een nieuwe rij aangemaakt in plaats van een update. Opgelost met `IS NOT DISTINCT FROM` in zowel de MAC- als hostname-matchquery.
- **"Auto-Cleanup" voor dubbele MAC-adressen deed niets** (`0 duplicate device(s) deactivated` ondanks een gemelde 38): de cleanup-query groepeerde duplicaten op `(mac_address, sensor_id)`, maar de detectiewidget groepeert alleen op `mac_address`. Rijen die door bovenstaande bug met verschillende `sensor_id` (`'soc-server'` vs leeg) waren ontstaan, telden voor de cleanup-logica dus niet als duplicaat. `cleanup_duplicate_mac_devices()` verwijdert nu ook expliciet "wees"-rijen met een lege `sensor_id` wanneer er voor diezelfde MAC al een rij met een echte sensor bestaat, zonder legitieme multi-sensor-duplicaten (zelfde device gezien door twee verschillende échte sensoren) aan te raken.
- **Vermoedelijke device-classificaties werden nooit opgeslagen/getoond.** `classify_all_devices()` schreef classificatiedata alleen weg bij confidence ≥ 0.7, maar de vendor-hint-methode (de enige methode die kan vuren vóórdat er een ML-model getraind is) levert altijd 0.6 op - een structureel gesloten deur. Metadata voor de "suggested classification"-UI wordt nu altijd weggeschreven zodra een device geclassificeerd wordt; het (voorzichtige) automatisch toewijzen van een template blijft ≥ 0.7 vereisen. De achtergrondtaak classificeerde bovendien alleen na een geslaagde modeltraining, terwijl trainingsdata zelf van vendor-hints afkomstig moet komen (kip-ei-probleem) - classificatie draait nu onafhankelijk van trainingssucces.
- **OUI (MAC-vendor) database werd nooit gebouwd tijdens installatie**, waardoor vendor-lookup (en dus vendor-gebaseerde classificatiesuggesties) voor de meeste devices leeg bleef. `update_oui_database.py` bestond al maar werd nergens automatisch aangeroepen. Toegevoegd als nieuwe Stap 7 in `post_install.sh`.

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
