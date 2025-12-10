# NetMonitor Project Workflow Instructions

## Before Making Changes

Voordat je wijzigingen voorstelt of code analyseert, MOET je het volgende doen:

### 1. Raadpleeg de Codebase Analyse
Het bestand `codebase_analysis.json` in de root van het project bevat een volledige analyse van de codebase met:
- Alle bestanden, klassen, functies en hun locaties
- Parameters en return types voor alle functies/methods
- Import dependencies (standard, external, local)
- Entry points (main functions, Flask routes, etc.)

**Gebruik dit bestand om:**
- Snel te vinden waar functionaliteit zich bevindt
- Te begrijpen welke parameters functies verwachten
- Dependencies en relaties tussen modules te identificeren
- Entry points en API routes te vinden

**Hoe te gebruiken:**
- Gebruik `Grep` met JSON paths om specifieke informatie te vinden
- Bijvoorbeeld: zoek naar een functienaam, klasse, of import
- Dit is sneller dan door meerdere bestanden zoeken

### 2. Standaard Workflow
1. **Taak begrijpen** - Lees de opdracht zorgvuldig
2. **Analyse fase** - Raadpleeg `codebase_analysis.json` voor relevante code locaties
3. **Code lezen** - Gebruik `Read` om de geïdentificeerde bestanden te lezen
4. **Planning** - Gebruik `TodoWrite` voor complexe taken (3+ stappen)
5. **Wijzigingen** - Gebruik `Edit` voor aanpassingen (bij voorkeur boven `Write`)
6. **Verificatie** - Run tests indien beschikbaar

### 3. Belangrijke Principes
- Nooit code wijzigen die je niet eerst gelezen hebt
- Minimale wijzigingen: alleen doen wat gevraagd wordt
- Let op security vulnerabilities (SQL injection, XSS, command injection, etc.)
- Gebruik bestaande patronen en conventies uit de codebase

## Project Specifieke Info

### Database
- SQLite database voor persistence
- Locatie: `/var/lib/netmonitor/netmonitor.db` (configureerbaar)
- Beheerd via `database.py` (DatabaseManager class)

### Configuratie
- YAML configuratie in `config.yaml`
- Database sync via `config_loader.py`
- Best practices in `config_defaults.py`

### Web Dashboard
- Flask applicatie in `web_dashboard.py`
- SocketIO voor real-time updates
- Authenticatie via `web_auth.py` en `sensor_auth.py`

### Monitoring
- Hoofdlogica in `netmonitor.py` (NetworkMonitor class)
- Threat detection in `detector.py` (ThreatDetector class)
- Behavior analysis in `behavior_detector.py`

### Testing
- Tests in `tests/` directory
- Run met: `pytest`
