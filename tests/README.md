# NetMonitor SOC - Test Suite

Comprehensive test suite voor het NetMonitor Security Operations Center platform.

## 📋 Overzicht

Deze test suite bevat:
- **Unit tests**: Testen individuele functies en klassen in isolatie
- **Integration tests**: Testen interacties tussen modules
- **Fixtures**: Herbruikbare test data en mock objecten

### Test Coverage

#### Unit Tests
- `test_detector.py` - ThreatDetector klasse (90+ tests)
  - IP parsing en whitelist/blacklist
  - Port scan detectie
  - Connection flood detectie
  - DNS tunneling detectie
  - Packet size anomalies
  - Threat feed integratie

- `test_database.py` - DatabaseManager klasse (40+ tests)
  - Connection pooling
  - Alert management
  - Traffic metrics
  - Sensor management
  - Whitelist CRUD
  - Configuration management

- `test_sensor_client.py` - SensorClient klasse (30+ tests)
  - Config loading en parsing
  - Server URL normalisatie
  - Sensor registratie
  - Config synchronisatie
  - Alert batching en upload
  - SSL verification

- `test_sensor_auth.py` - SensorAuthManager klasse (20+ tests)
  - Token generatie en validatie
  - Permission management
  - Token revocation
  - Security aspecten

- `test_alerts.py` - AlertManager klasse (20+ tests)
  - Alert sending (console/file/syslog)
  - Rate limiting
  - Severity handling

- `test_web_dashboard.py` - Flask API routes (30+ tests)
  - API endpoints
  - Authentication
  - Error handling
  - Input validation

#### Integration Tests
- `test_detector_database_integration.py` - Detector ↔ Database
  - Alert flow van packet naar database
  - Whitelist synchronisatie
  - High volume performance

- `test_sensor_server_integration.py` - Sensor ↔ Server
  - Sensor registratie en authentication
  - Alert upload workflow
  - Config synchronisatie
  - End-to-end workflows

**Totaal: 230+ tests**

## 🚀 Installatie

### 1. Installeer test dependencies

```bash
pip install -r requirements-test.txt
```

### 2. Maak logs directory aan

```bash
mkdir -p tests/logs
```

## ▶️ Tests Uitvoeren

### Alle tests

```bash
pytest
```

### Alleen unit tests

```bash
pytest tests/unit/
```

### Alleen integration tests

```bash
pytest tests/integration/
```

### Specifieke test file

```bash
pytest tests/unit/test_detector.py
```

### Specifieke test functie

```bash
pytest tests/unit/test_detector.py::TestPortScanDetection::test_port_scan_detection_triggers
```

### Met verbose output

```bash
pytest -v
```

### Met coverage report

```bash
pytest --cov=. --cov-report=html
```

### Parallel uitvoeren (sneller)

```bash
pytest -n auto
```

## 🏷️ Test Markers

Tests zijn georganiseerd met markers voor selectieve uitvoering:

```bash
# Alleen unit tests
pytest -m unit

# Alleen integration tests
pytest -m integration

# Alleen database tests
pytest -m database

# Alleen slow tests
pytest -m slow

# Skip slow tests
pytest -m "not slow"

# Network tests
pytest -m network
```

### Beschikbare markers:
- `unit` - Unit tests voor individuele functies
- `integration` - Integration tests voor module interacties
- `slow` - Tests die langer dan 1 seconde duren
- `network` - Tests die netwerk toegang nodig hebben
- `database` - Tests die database toegang nodig hebben
- `smoke` - Smoke tests voor basis functionaliteit

## 📊 Coverage Rapportage

### Genereer HTML coverage report

```bash
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

### Toon coverage in terminal

```bash
pytest --cov=. --cov-report=term-missing
```

### Coverage voor specifieke module

```bash
pytest --cov=detector --cov-report=html tests/unit/test_detector.py
```

## 🛠️ Test Fixtures

Herbruikbare fixtures zijn gedefinieerd in `conftest.py`:

### Configuratie Fixtures
- `base_config` - Basis NetMonitor configuratie
- `config_file` - Tijdelijke config file
- `sensor_config` - Sensor-specifieke configuratie

### Database Fixtures
- `mock_db_connection` - Mock PostgreSQL connectie
- `mock_db_manager` - Mock DatabaseManager

### Network/Packet Fixtures
- `mock_packet` - Mock Scapy packet
- `sample_packets` - Diverse packet types

### Detector Fixtures
- `mock_threat_feed_manager` - Mock ThreatFeedManager
- `mock_behavior_detector` - Mock BehaviorDetector
- `mock_abuseipdb_client` - Mock AbuseIPDB client

### Sensor/Auth Fixtures
- `mock_sensor_auth` - Mock SensorAuthManager
- `mock_requests` - Mock HTTP requests

### Flask Fixtures
- `flask_app` - Flask test client

## 📝 Nieuwe Tests Schrijven

### Unit Test Template

```python
import pytest
from unittest.mock import Mock, MagicMock, patch

@pytest.mark.unit
class TestMijnFunctionaliteit:
    """Test beschrijving"""

    def test_normal_case(self, base_config):
        """
        Test: Normale situatie
        Normal case: Beschrijving
        """
        # Arrange
        input_data = ...

        # Act
        result = mijn_functie(input_data)

        # Assert
        assert result == expected

    def test_edge_case(self, base_config):
        """
        Test: Edge case beschrijving
        Edge case: Specifieke situatie
        """
        # Test code

    def test_error_handling(self):
        """
        Test: Error handling
        Error case: Wat kan fout gaan
        """
        with pytest.raises(ExpectedException):
            problematic_function()
```

### Integration Test Template

```python
import pytest
from unittest.mock import Mock, patch

@pytest.mark.integration
class TestModuleIntegration:
    """Test integratie tussen modules"""

    def test_module_interaction(self, mock_db_manager):
        """
        Integration test: Module A → Module B
        Normal case: Data flow tussen modules
        """
        # Setup
        module_a = ModuleA()
        module_b = ModuleB(module_a)

        # Execute
        result = module_b.process()

        # Verify
        assert result is not None
```

## 🎯 Best Practices

### 1. Test Naming Convention
- Test files: `test_<module>.py`
- Test classes: `Test<Functionality>`
- Test functions: `test_<scenario>`

### 2. Test Structure (AAA Pattern)
```python
def test_example():
    # Arrange - Setup test data
    input_data = prepare_test_data()

    # Act - Execute function under test
    result = function_to_test(input_data)

    # Assert - Verify results
    assert result == expected_output
```

### 3. Gebruik Fixtures
Hergebruik fixtures in plaats van duplicate setup code:
```python
def test_with_fixture(base_config, mock_db_manager):
    # Fixtures zijn automatisch beschikbaar
    detector = ThreatDetector(base_config, db_manager=mock_db_manager)
```

### 4. Mock Externe Dependencies
```python
@patch('module.external_api_call')
def test_function(mock_api):
    mock_api.return_value = {'success': True}
    result = my_function()
    assert result is not None
```

### 5. Test Edge Cases
Test niet alleen de "happy path", maar ook:
- Empty inputs
- None values
- Boundary conditions
- Error scenarios

### 6. Gebruik Descriptive Assertions
```python
# Goed
assert len(alerts) == 3, f"Expected 3 alerts, got {len(alerts)}"

# Minder goed
assert len(alerts) == 3
```

## 🐛 Debugging Tests

### Run met print statements

```bash
pytest -s tests/unit/test_detector.py
```

### Run met pdb debugger

```bash
pytest --pdb
```

### Stop bij eerste failure

```bash
pytest -x
```

### Toon locals bij failure

```bash
pytest -l
```

### Verbose traceback

```bash
pytest --tb=long
```

## 📈 Performance Testing

### Benchmark tests

```bash
pytest --benchmark-only
```

### Profiling

```bash
pytest --profile
```

## 🔄 Continuous Integration

### Pre-commit hook

Create `.git/hooks/pre-commit`:
```bash
#!/bin/bash
pytest tests/unit/ -x
if [ $? -ne 0 ]; then
    echo "Tests failed, commit aborted"
    exit 1
fi
```

### GitHub Actions workflow

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: pip install -r requirements-test.txt
      - name: Run tests
        run: pytest --cov=. --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## 📚 Documentatie

Elke test heeft documentatie in het volgende formaat:

```python
def test_example(self):
    """
    Test: Korte beschrijving van wat getest wordt
    Normal case/Edge case/Error case: Specifieke situatie
    """
```

Dit helpt om snel te begrijpen:
- **Wat** wordt getest
- **Waarom** deze test belangrijk is
- **Welk scenario** wordt gecovered

## 🎓 Meer Informatie

- [Pytest Documentation](https://docs.pytest.org/)
- [Python unittest.mock](https://docs.python.org/3/library/unittest.mock.html)
- [Test-Driven Development](https://en.wikipedia.org/wiki/Test-driven_development)

## 📞 Support

Voor vragen over de test suite, zie de hoofddocumentatie of contacteer het development team.
