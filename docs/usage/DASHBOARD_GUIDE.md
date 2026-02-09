# NetMonitor SOC — Dashboard Handleiding

**Praktische handleiding voor dagelijks gebruik van het NetMonitor Dashboard**

Versie: 1.0
Laatst bijgewerkt: Februari 2026

> **Over deze handleiding:** Dit document is bedoeld voor operators en analisten die het NetMonitor dashboard gebruiken via de webbrowser. Alle instructies zijn stap-voor-stap uitgelegd aan de hand van wat u op het scherm ziet. Voor technische details (API, database, command line) verwijzen we naar de [Admin Manual](ADMIN_MANUAL.md).

---

## Inhoudsopgave

1. [Inloggen](#1-inloggen)
2. [Dashboard Overzicht](#2-dashboard-overzicht)
3. [Alerts Bekijken](#3-alerts-bekijken)
4. [Alerts Afhandelen](#4-alerts-afhandelen)
5. [Sensors Beheren](#5-sensors-beheren)
6. [Configuratie Aanpassen](#6-configuratie-aanpassen)
7. [Whitelist Beheren](#7-whitelist-beheren)
8. [Device Classification](#8-device-classification)
9. [Templates en Behavior Rules](#9-templates-en-behavior-rules)
10. [Praktische Scenario's](#10-praktische-scenarios)
11. [Tips en Veelgestelde Vragen](#11-tips-en-veelgestelde-vragen)

---

## 1. Inloggen

### Inlogscherm

Open uw webbrowser en ga naar het adres van uw NetMonitor server (u ontvangt dit van uw beheerder).

U ziet het inlogscherm met twee velden:

1. **Gebruikersnaam** — Voer uw gebruikersnaam in
2. **Wachtwoord** — Voer uw wachtwoord in (minimaal 12 tekens)

Klik op **"Login"** om in te loggen.

### Tweefactorauthenticatie (2FA)

Als 2FA is ingeschakeld, verschijnt er na het inloggen een extra scherm:

1. Open uw authenticator-app (Google Authenticator, Microsoft Authenticator, of Authy)
2. Zoek de vermelding **"NetMonitor SOC"**
3. Voer de 6-cijferige code in die u ziet
4. Klik op **"Verify"**

Als u geen toegang meer heeft tot uw authenticator-app, gebruik dan een eenmalige back-upcode.

### Wachtwoord Wijzigen

1. Klik rechtsboven op uw **gebruikersnaam**
2. Kies **"Profile Settings"** uit het dropdown-menu
3. Voer uw huidige wachtwoord in
4. Voer tweemaal uw nieuwe wachtwoord in
5. Klik op **"Save"**

### 2FA Instellen

1. Klik rechtsboven op uw **gebruikersnaam**
2. Kies **"Two-Factor Auth"**
3. Scan de QR-code met uw authenticator-app
4. Voer de bevestigingscode in
5. Sla uw back-upcodes veilig op

### Rollen

Wat u kunt zien en doen hangt af van uw rol:

| Rol | Rechten |
|-----|---------|
| **Viewer** | Dashboard bekijken, alerts en sensors inzien (alleen-lezen) |
| **Operator** | Alles van Viewer + sensors beheren, alerts afhandelen, configuratie wijzigen |
| **Admin** | Alles + gebruikersbeheer en systeemconfiguratie |

---

## 2. Dashboard Overzicht

Na het inloggen ziet u het hoofddashboard. Dit bestaat uit de volgende onderdelen:

### Navigatiebalk (bovenaan)

Bovenaan het scherm ziet u de navigatiebalk met:

- **"NetMonitor SOC Dashboard"** — titel, klik om terug te keren naar het hoofdscherm
- **Tabbladen**: Alerts, Sensors, Config, Whitelist
- **Rechtsboven**: uw gebruikersnaam (dropdown-menu) en knoppen voor meldingen en vernieuwen

### Systeemmetrieken (linkerzijde)

Vier gekleurde meters ("gauges") tonen de huidige status:

| Meter | Wat het toont | Gezond bereik |
|-------|---------------|---------------|
| **CPU** | Processorgebruik van de server | Onder 80% |
| **RAM** | Geheugengebruik van de server | Onder 85% |
| **Packets/sec** | Aantal verwerkte pakketten per seconde | Varieert per netwerk |
| **Alerts/min** | Aantal nieuwe alerts per minuut | Zo laag mogelijk |

### Alert Feed (centraal)

Het centrale gedeelte toont de **real-time alert feed** — een doorlopende lijst van beveiligingsmeldingen. Nieuwe alerts verschijnen bovenaan.

**Kleurcodes:**

| Kleur | Severity | Betekenis |
|-------|----------|-----------|
| **Rood** | HIGH / CRITICAL | Ernstige dreiging, directe actie vereist |
| **Oranje** | MEDIUM | Verdachte activiteit, onderzoek nodig |
| **Geel** | LOW | Informatief, mogelijk onschadelijk |

Elke alert toont:
- **Severity badge** (rood/oranje/geel)
- **Alert type** (bijv. "Port Scan Detected")
- **Bron-IP** → **Doel-IP** met hostnamen indien beschikbaar
- **Tijdstip**

### Verkeersgrafieken (onder de meters)

- **Bandbreedte-grafiek** — Toont het dataverkeer over de afgelopen periode
- **Packets/seconde-grafiek** — Toont de pakketten per seconde over tijd
- **Protocol verdeling** — Verhouding TCP/UDP/ICMP verkeer

### Top Talkers

Een lijst van de IP-adressen met het meeste verkeer:

- **IP-adres** met hostname (indien beschikbaar)
- **Landvlag** voor externe IP-adressen (bijv. 🇳🇱 NL, 🇺🇸 US)
- **"Local"** voor interne IP-adressen
- **Verkeer in/uit** — hoeveel data is verstuurd/ontvangen

---

## 3. Alerts Bekijken

### Alert Feed

Het tabblad **Alerts** toont alle beveiligingsmeldingen. De lijst scrollt automatisch mee met nieuwe alerts.

### Alert Details Openen

Klik op een alert in de feed om het detailvenster te openen. U ziet:

- **Alert Type** — Wat voor soort alert (bijv. Port Scan, Brute Force)
- **Severity** — Ernst van de melding
- **Bron-IP** — Het IP-adres dat het verkeer verstuurt, met hostname indien beschikbaar
- **Doel-IP** — Het IP-adres dat het verkeer ontvangt, met hostname indien beschikbaar
- **Poort(en)** — Welke poorten betrokken zijn
- **Tijdstip** — Wanneer de alert werd gegenereerd
- **Sensor** — Welke sensor dit detecteerde
- **Details** — Aanvullende informatie over de detectie
- **Land** — Landcode en vlag voor externe IP-adressen

### Hostname Informatie

Bij alerts worden IP-adressen waar mogelijk aangevuld met hostnamen. Dit helpt om snel te herkennen welk apparaat betrokken is (bijv. "printer-2e-verdieping.local" in plaats van alleen "192.168.1.45").

### Severity Uitleg

| Severity | Betekenis | Voorbeelden | Actie |
|----------|-----------|-------------|-------|
| **CRITICAL** | Bevestigde dreiging | C2 communicatie, bekende malware-IP | Onmiddellijk handelen |
| **HIGH** | Waarschijnlijke dreiging | Port scan, brute force aanval, DDoS | Snel onderzoeken |
| **MEDIUM** | Verdachte activiteit | DNS tunneling, ongebruikelijke poorten | Onderzoeken |
| **LOW** | Informatief | Protocol anomalie, hoog verkeer | Monitoren |

### Filteren

**Op severity:**
Klik op een severity-badge (rood/oranje/geel) bovenaan de alert feed om te filteren.

**Op tijd:**
Selecteer een tijdsperiode: Afgelopen uur, 6 uur, 24 uur, of 7 dagen.

**Op bron:**
Gebruik de filtervelden om te filteren op:
- Sensor
- Bron-IP
- Alert type
- Land

---

## 4. Alerts Afhandelen

### Workflow

De standaard workflow voor het afhandelen van alerts:

**Stap 1 — Onderzoeken**
1. Klik op de alert om details te bekijken
2. Controleer het bron-IP: is dit een bekend apparaat?
3. Controleer het doel-IP: is dit een intern systeem?
4. Bekijk de poorten en het type verkeer
5. Controleer of er meer alerts zijn van hetzelfde IP (zoek in de feed)

**Stap 2 — Beoordelen**

| Conclusie | Volgende stap |
|-----------|---------------|
| **False positive** (vals alarm) | Voeg bron-IP toe aan whitelist, of maak een template rule |
| **Echte dreiging** | Blokkeer het IP op uw firewall, onderzoek het doelsysteem |
| **Onduidelijk** | Blijf monitoren, verzamel meer informatie |

**Stap 3 — Actie ondernemen**

- **False positive oplossen**: Ga naar het tabblad Whitelist en voeg het IP toe (zie [sectie 7](#7-whitelist-beheren)), of maak een behavior rule in een template (zie [sectie 9](#9-templates-en-behavior-rules))
- **Dreiging blokkeren**: Blokkeer het IP-adres op uw firewall of router

**Stap 4 — Acknowledgen (bevestigen)**

Na afhandeling:
1. Klik op de alert
2. Klik op **"Acknowledge"**
3. Voeg eventueel een notitie toe
4. De alert wordt gemarkeerd als beoordeeld

---

## 5. Sensors Beheren

### Sensor Overzicht

Klik op het tabblad **Sensors** om alle sensors te zien.

Per sensor ziet u:
- **Status-indicator**: groen (online) of rood (offline)
- **Naam** van de sensor
- **Locatie** (indien ingesteld)
- **IP-adres**
- **Prestatie**: CPU, RAM, bandbreedte
- **Laatst gezien** — wanneer de sensor voor het laatst communiceerde
- **Actieknoppen**

### Status Betekenis

| Status | Kleur | Betekenis |
|--------|-------|-----------|
| **Online** | Groen | Sensor werkt normaal, communicatie is recent |
| **Offline** | Rood | Sensor reageert niet, mogelijk uitgevallen |

Een sensor wordt als offline beschouwd als er langer dan 5 minuten geen communicatie is geweest.

### Sensor Acties

Naast elke sensor staan actieknoppen:

**Update** (blauwe knop)
- Werkt de sensor-software bij naar de nieuwste versie
- De sensor herstart automatisch
- Korte onderbreking van circa 30 seconden

**Reboot** (gele knop)
- Herstart het volledige sensorsysteem
- Gebruik dit bij systeemproblemen
- Onderbreking van 1-5 minuten
- U moet de sensornaam intypen ter bevestiging

**Instellingen** (tandwiel/schuifbalken-knop)
- Opent een venster met sensor-instellingen
- Zie hieronder voor details

**Verwijderen** (rode knop)
- Verwijdert de sensor permanent inclusief alle gegevens
- Kan niet ongedaan worden gemaakt
- Gebruik alleen bij het buiten dienst stellen van een sensor

### Sensor Instellingen Aanpassen

1. Klik op de **instellingenknop** (schuifbalken-icoon) naast de sensor
2. Het instellingenvenster opent met de volgende opties:

| Instelling | Wat het doet | Standaard |
|------------|--------------|-----------|
| **Sensor Location** | Beschrijving van de fysieke locatie | Leeg |
| **Internal Networks** | Welke netwerken als "intern" worden beschouwd (één per regel) | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 |
| **Heartbeat Interval** | Hoe vaak de sensor rapporteert (in seconden) | 30 seconden |
| **Config Sync Interval** | Hoe vaak de sensor nieuwe instellingen ophaalt (in seconden) | 300 seconden (5 minuten) |

3. Pas de gewenste instellingen aan
4. Klik op **"Save Settings"**
5. De sensor past de instellingen automatisch toe bij de volgende synchronisatie

---

## 6. Configuratie Aanpassen

### Detectie Regels

Klik op het tabblad **Config** om de detectie-instellingen te openen.

U ziet een lijst van alle detectieregels:

| Regel | Wat het detecteert |
|-------|-------------------|
| Port Scan Detection | IP-adressen die meerdere poorten scannen |
| Brute Force Detection | Herhaalde mislukte inlogpogingen |
| DNS Tunneling Detection | Verdachte DNS-patronen (data exfiltratie) |
| Large File Transfer | Ongebruikelijk grote bestandsoverdrachten |
| DDoS Detection | Abnormaal hoge verkeersvolumes |
| Unusual Port Activity | Verkeer op ongebruikelijke poorten |
| Internal Scanning | Interne apparaten die andere interne apparaten scannen |
| Protocol Anomaly | Afwijkend protocolgebruik |
| Beacon Detection | Regelmatige "check-in" communicatie (malware-indicator) |
| Data Exfiltration | Grote hoeveelheden data die het netwerk verlaten |
| Malware Communication | Communicatiepatronen die op malware lijken |
| Lateral Movement | Zijwaartse beweging binnen het netwerk |
| Suspicious DNS | Verdachte DNS-verzoeken |

### Regels In-/Uitschakelen

Per regel kunt u:
1. Het **selectievakje** aan- of uitvinken om de regel te activeren/deactiveren
2. De **drempelwaarde** (threshold) aanpassen — een hoger getal betekent minder alerts, een lager getal betekent strengere detectie

### Drempelwaarden Aanpassen

**Voorbeeld: Port Scan Detection**
- Standaard: alert bij 10 unieke poorten
- Veel false positives? Verhoog naar 20-30
- Scans gemist? Verlaag naar 5

**Voorbeeld: Brute Force Detection**
- Standaard: alert bij 5 mislukte pogingen
- Strenger: verlaag naar 3
- Minder ruis: verhoog naar 10

### Wijzigingen Opslaan

1. Pas de gewenste waarden aan
2. Kies het **bereik**:
   - **Globaal** — geldt voor alle sensors
   - **Per sensor** — overschrijving voor één specifieke sensor
3. Klik op **"Save Changes"**
4. Sensors passen de instellingen automatisch toe binnen 5 minuten

### Standaardwaarden Herstellen

Klik op **"Reset to Best Practice Defaults"** om alle instellingen terug te zetten naar de aanbevolen waarden. U wordt gevraagd om dit te bevestigen.

---

## 7. Whitelist Beheren

### Wat is de Whitelist?

De whitelist bevat IP-adressen en netwerken waarvan u weet dat ze vertrouwd zijn. Verkeer van/naar gewhiteliste adressen genereert geen alerts.

**Gebruik de whitelist voor:**
- Interne servers
- Vertrouwde externe diensten
- Backup-systemen
- Monitoringtools
- Beheerderswerkstations

### Whitelist Openen

Klik op het tabblad **Whitelist** in de navigatiebalk.

U ziet een tabel met bestaande regels:
- **Source IP** — Bron-IP of netwerk
- **Target IP** — Doel-IP of netwerk
- **Port(s)** — Poortfilter (leeg = alle poorten)
- **Description** — Omschrijving
- **Scope** — Globaal of per sensor

### Whitelist Regel Toevoegen

1. Klik op **"Add Entry"**
2. Vul de velden in:

| Veld | Wat invullen | Voorbeeld |
|------|-------------|-----------|
| **Source IP/CIDR** | Het IP-adres of netwerk van de bron | `192.168.1.50` of `10.0.0.0/8` |
| **Target IP/CIDR** | Het IP-adres of netwerk van het doel | `192.168.1.1` |
| **Port(s)** | Poort(en) om te whitelisten | `443` of `80,443` of `8080-8090` |
| **Description** | Korte omschrijving | "Admin werkstation" |
| **Scope** | Bereik van de regel | Globaal of per sensor |

Laat een veld leeg om alles te matchen voor die dimensie. U moet minimaal Source IP of Target IP invullen.

3. Klik op **"Add"**

### CIDR Notatie Uitleg

CIDR notatie geeft een netwerkreeks aan:

| Notatie | Betekenis | Aantal adressen |
|---------|-----------|-----------------|
| `192.168.1.50` | Eén specifiek IP-adres | 1 |
| `192.168.1.0/24` | Alles van 192.168.1.0 t/m 192.168.1.255 | 256 |
| `10.0.0.0/8` | Alles van 10.0.0.0 t/m 10.255.255.255 | 16 miljoen+ |

### Poortfilter Opties

| Formaat | Voorbeeld | Betekenis |
|---------|-----------|-----------|
| Enkele poort | `443` | Alleen poort 443 |
| Meerdere poorten | `80,443,8080` | Poort 80, 443 en 8080 |
| Poortreeks | `8080-8090` | Poorten 8080 t/m 8090 |
| Gecombineerd | `80,443,8080-8090` | Combinatie |
| Leeg | | Alle poorten |

### Whitelist Regel Verwijderen

1. Zoek de regel in de tabel
2. Klik op de **verwijderknop** (prullenbak-icoon) naast de regel
3. Bevestig de verwijdering

De sensor past de wijziging toe binnen 5 minuten.

### Whitelist vs. Templates

| Aspect | Whitelist | Template Behavior Rule |
|--------|-----------|----------------------|
| **Werking** | Onderdrukt **alle** alerts voor een IP | Onderdrukt alleen alerts voor **specifiek gedrag** |
| **Bereik** | Per IP-adres/netwerk | Per apparaattype (template) |
| **Wanneer gebruiken** | Volledig vertrouwde systemen | Apparaten met deels verwacht verkeer |
| **Risico** | Kan echte dreigingen missen | Nauwkeuriger, minder risico |

**Aanbeveling:** Gebruik waar mogelijk templates met behavior rules in plaats van whitelisting. Dit is nauwkeuriger en veiliger.

---

## 8. Device Classification

### Openen

Op het hoofddashboard vindt u de sectie **"Device Classification"**. Klik op de titel om deze uit te klappen.

U ziet bovenaan twee badges:
- **Blauw getal**: Totaal aantal ontdekte apparaten in uw netwerk
- **Groen getal**: Aantal geclassificeerde apparaten (met een template)

### Tabbladen

De Device Classification sectie heeft 4 tabbladen:

| Tabblad | Functie |
|---------|---------|
| **Devices** | Alle ontdekte apparaten bekijken en beheren |
| **Templates** | Apparaatprofielen aanmaken en beheren |
| **Service Providers** | Bekende diensten (Netflix, YouTube, etc.) beheren |
| **Statistics** | Overzicht en statistieken bekijken |

### Devices Tabblad

Dit tabblad toont alle apparaten die in uw netwerk zijn ontdekt.

**Per apparaat ziet u:**

| Kolom | Wat het toont |
|-------|-------------|
| **IP Address** | IP-adres van het apparaat |
| **Hostname** | Naam van het apparaat (indien beschikbaar) |
| **MAC / Vendor** | Hardware-adres en fabrikant |
| **Template** | Toegewezen profiel, of "Unclassified" |
| **Learning Status** | Hoever het systeem is met het leren van gedrag |
| **Last Seen** | Wanneer het apparaat laatst actief was |

**Zoeken:** Typ in de zoekbalk om te filteren op IP-adres, hostname, MAC-adres of fabrikant.

**Filteren op template:** Gebruik het dropdown-menu om alleen apparaten van een bepaald type te tonen, of selecteer "Unclassified" om ongeclassificeerde apparaten te vinden.

**Learning Status uitleg:**

| Status | Betekenis |
|--------|-----------|
| **Not Started** | Nog geen verkeer geanalyseerd — wacht af |
| **Learning (N)** | N pakketten geanalyseerd, nog niet genoeg (<100) |
| **Ready** | 100+ pakketten verwerkt, profiel is compleet |

Bij apparaten met 50+ pakketten wordt automatisch een ML-classificatie uitgevoerd. U ziet dan het voorgestelde apparaattype en een betrouwbaarheidsscore. Apparaten met >70% betrouwbaarheid worden automatisch geclassificeerd.

**Apparaat details bekijken:**

1. Klik op een apparaat in de lijst
2. Er opent een detailvenster met:
   - IP-adres, hostname, MAC-adres en fabrikant
   - Learning statistieken (aantal pakketten, unieke poorten)
   - Classification hints (suggesties op basis van geobserveerd gedrag)
   - Template dropdown om een profiel toe te wijzen

**Template toewijzen aan apparaat:**

1. Klik op het apparaat
2. Selecteer een template uit de dropdown-lijst
3. Klik op **"Apply Template"**
4. Het apparaat wordt nu geclassificeerd — verwacht verkeer genereert geen alerts meer

### Templates Tabblad

Dit tabblad toont alle beschikbare templates als kaarten.

**Per template ziet u:**
- Icoon van het apparaattype
- Naam
- Categorie (IoT, Network, Server, Workstation, Mobile)
- Badge: "Built-in" (standaard meegeleverd) of "Custom" (zelf aangemaakt)
- Aantal apparaten dat deze template gebruikt

**Filteren:** Gebruik het categorie-dropdown om te filteren op type.

**Built-in templates** zijn standaard meegeleverd en kunnen niet worden gewijzigd of verwijderd. Voorbeelden: IP Camera, Smart TV, Network Printer, Router/Firewall, DNS Server, Web Server, Workstation.

**Template details bekijken:**
Klik op een template kaart om de details te openen. U ziet de behavior rules, instellingen en welke apparaten deze template gebruiken.

### Service Providers Tabblad

Dit tabblad toont bekende internetdiensten (streaming, CDN, cloud). Verkeer naar deze diensten wordt als normaal beschouwd.

**Meegeleverde providers:** Netflix, YouTube, Spotify, Microsoft 365, AWS, Cloudflare, en meer.

**Filteren:** Gebruik het categorie-dropdown (Streaming, CDN, Cloud, Social, Gaming).

**Provider toevoegen:**
1. Klik op **"Add Provider"**
2. Vul in: naam, categorie, IP-reeksen, domeinen en beschrijving
3. Klik op **"Create"**

**Provider verwijderen:**
1. Klik op het prullenbak-icoon naast de provider
2. Bevestig de verwijdering

Built-in providers kunnen niet worden verwijderd.

### Statistics Tabblad

Dit tabblad geeft een overzicht van uw netwerkapparaten:

| Kaart | Wat het toont |
|-------|-------------|
| **Total Devices** | Totaal aantal ontdekte apparaten |
| **Classified** | Apparaten met een template |
| **Unclassified** | Apparaten zonder template |

Daaronder ziet u:
- **Devices by Template** — Hoeveel apparaten per template
- **Devices by Vendor** — Top 10 fabrikanten in uw netwerk

---

## 9. Templates en Behavior Rules

### Template Aanmaken

1. Ga naar het **Templates** tabblad
2. Klik op **"Create Template"**
3. Vul de velden in:
   - **Name**: Unieke naam (bijv. "VoIP Telefoon", "NAS Synology")
   - **Category**: Selecteer een categorie (IoT, Network, Server, Workstation, Mobile)
   - **Icon**: Kies een passend icoon
   - **Description**: Korte omschrijving van het apparaattype
4. Klik op **"Create"**
5. De template verschijnt in de lijst — open deze om behavior rules toe te voegen

### Template Klonen

U kunt een bestaande template kopiëren om snel een variant te maken. Dit werkt ook met Built-in templates (die normaal niet bewerkbaar zijn).

1. Open de template die u wilt kopiëren
2. Klik op de **"Clone"** knop
3. Geef de kopie een nieuwe naam
4. Pas de rules aan naar behoefte

### Template Verwijderen

1. Open de template
2. Klik op **"Delete Template"** (rode knop)
3. Bevestig de verwijdering

Built-in templates kunnen niet worden verwijderd. Apparaten die deze template gebruikten worden "Unclassified".

### Template Genereren uit Geleerd Gedrag

Als het systeem genoeg pakketten van een apparaat heeft geanalyseerd (100+, status "Ready"), kunt u automatisch een template laten genereren:

1. Ga naar het **Devices** tabblad
2. Zoek het apparaat (op IP of MAC)
3. Controleer dat de Learning Status **"Ready"** is
4. Klik op het apparaat
5. Klik op **"Create Template from Learned Behavior"**
6. Geef de template een naam
7. Controleer de automatisch gegenereerde rules
8. Pas aan indien nodig

### Behavior Rules

Behavior rules definiëren wat "normaal" gedrag is voor een apparaat. Verkeer dat matcht met deze regels genereert geen alerts.

### Behavior Rule Toevoegen

1. Open een template (niet Built-in)
2. Klik op **"Add Rule"**
3. Selecteer het **Type**:

| Type | Wat het doet |
|------|-------------|
| **Allowed Ports** | Welke poorten normaal zijn |
| **Allowed Protocols** | Welke protocollen normaal zijn (TCP, UDP, ICMP) |
| **Allowed Sources** | Welke IP-adressen mogen verbinden (voor servers) |
| **Expected Destinations** | Waar het apparaat naartoe mag communiceren |
| **Bandwidth Limit** | Maximale bandbreedte (alert bij overschrijding) |
| **Connection Behavior** | Hoe het apparaat verbindingen afhandelt |
| **Traffic Pattern** | Verwacht verkeerspatroon |
| **Suppress Alert Types** | Specifieke alert types onderdrukken |
| **Time Restrictions** | Tijdsgebonden regels |
| **DNS Behavior** | Verwachte DNS-patronen |

4. Voer de **Value** in (afhankelijk van het type):
   - Poorten: `443` of `80,443,8080` of `5060-5090`
   - Protocol: `TCP`, `UDP`, of `ICMP`
   - IP/netwerk: `192.168.1.0/24`
   - Domein: `*.example.com`
   - Alert type: `HTTP_SENSITIVE_DATA`
5. Selecteer de **Direction** (richting):
   - **Inbound** — verkeer **naar** het apparaat (apparaat ontvangt)
   - **Outbound** — verkeer **van** het apparaat (apparaat verstuurt)
   - **Beide** — ongeacht de richting
6. Selecteer de **Action**:
   - **Allow** — verkeer wordt als normaal beschouwd
   - **Suppress** — alerts worden volledig verborgen
   - **Alert** — altijd een alert genereren (voor monitoring)
7. (Optioneel) Voeg een **Description** toe
8. Klik op **"Add"**

### Behavior Rule Verwijderen

1. Open de template
2. Klik op het **prullenbak-icoon** naast de regel
3. Bevestig de verwijdering

### Direction (Richting) Uitleg

De richting bepaalt wanneer een regel wordt geëvalueerd:

| Richting | Wat het betekent | Voorbeeld |
|----------|-----------------|-----------|
| **Inbound** | Verkeer dat het apparaat **ontvangt** | Een webserver die verbindingen ontvangt op poort 443 |
| **Outbound** | Verkeer dat het apparaat **verstuurt** | Een camera die beelden streamt naar een recorder |
| **Beide** | Alle verkeer van en naar het apparaat | Algemene protocolregel |

### Suppress Alert Types

Met dit type kunt u **specifieke** alert types onderdrukken zonder andere detecties uit te schakelen. Dit is veel nauwkeuriger dan een IP whitelist.

**Wanneer gebruiken:**
- Een apparaat veroorzaakt steeds dezelfde false positive
- U wilt dat apparaat wél monitoren op andere dreigingen
- Voorbeeld: een UniFi controller die configuratiedata verstuurt die ten onrechte als "gevoelige data" wordt gedetecteerd

**Verschil met IP whitelist:**
- Een whitelist onderdrukt **alle** alerts voor een IP → u mist mogelijk echte dreigingen
- Suppress Alert Types onderdrukt alleen de **genoemde** types → andere detectie blijft actief

**Toevoegen:**
1. Open de template
2. Klik **"Add Rule"**
3. Type: **Suppress Alert Types**
4. Value: het alert type dat u wilt onderdrukken (bijv. `HTTP_SENSITIVE_DATA`)
5. Klik **"Add"**

### Bidirectionele Checking

Het systeem controleert templates van **beide** apparaten bij een verbinding:
- Is het **bron-apparaat** volgens zijn template dit verkeer mogen versturen?
- Is het **doel-apparaat** volgens zijn template dit verkeer mogen ontvangen?

Als één van beide apparaten een matchende rule heeft, wordt de alert onderdrukt. Bijvoorbeeld: een NAS met een inbound rule voor poort 445 voorkomt SMB-alerts wanneer werkstations verbinden.

---

## 10. Praktische Scenario's

### Scenario 1: Nieuwe IP Camera Installeren

**Situatie:** U heeft een nieuwe IP-camera geïnstalleerd en wilt voorkomen dat het RTSP-verkeer alerts genereert.

**Stappen:**
1. Wacht tot de camera verschijnt in het **Devices** tabblad (dit gebeurt automatisch)
2. Klik op de camera in de apparatenlijst
3. Selecteer de template **"IP Camera"** uit de dropdown
4. Klik op **"Apply Template"**
5. Klaar — RTSP-verkeer van de camera genereert geen alerts meer

### Scenario 2: VoIP Template Maken voor Kantoortelefoons

**Situatie:** U heeft VoIP-telefoons die SIP en RTP gebruiken. U wilt een template maken zodat dit verkeer als normaal wordt beschouwd.

**Stappen:**
1. Ga naar het **Templates** tabblad
2. Klik op **"Create Template"**
3. Vul in: Naam "Office VoIP Phone", Categorie "IoT"
4. Klik op **"Create"**
5. Open de nieuwe template
6. Klik op **"Add Rule"** en voeg deze regels toe:
   - Type: **Allowed Ports**, Value: `5060-5090`, Description: "SIP signaling"
   - Type: **Allowed Ports**, Value: `10000-20000`, Description: "RTP media"
   - Type: **Allowed Protocols**, Value: `UDP`, Description: "Voice protocol"
7. Ga naar het **Devices** tabblad
8. Zoek uw VoIP-telefoons
9. Wijs de template **"Office VoIP Phone"** toe aan elk toestel

### Scenario 3: UniFi Controller — False Positives Onderdrukken

**Situatie:** Uw UniFi Controller stuurt configuratiedata naar access points. Dit wordt ten onrechte gedetecteerd als "sensitive data". U wilt deze specifieke false positives onderdrukken, maar andere detecties (brute force, port scan) moeten actief blijven.

**Stappen:**
1. Ga naar het **Templates** tabblad
2. Klik op **"Create Template"**
3. Vul in: Naam "UniFi Controller", Categorie "Network"
4. Klik op **"Create"**
5. Open de template en voeg regels toe:
   - Type: **Allowed Ports**, Value: `8443,8080,8843`, Direction: Inbound, Description: "Management poorten"
   - Type: **Suppress Alert Types**, Value: `HTTP_SENSITIVE_DATA,HTTP_HIGH_ENTROPY_PAYLOAD`, Description: "Management traffic false positives"
   - Type: **Allowed Sources**, Value: `internal`, Description: "Alleen interne apparaten"
6. Ga naar **Devices** en wijs de template toe aan uw UniFi Controller
7. Klaar — de false positives verdwijnen, maar brute force en port scan detectie blijven actief

### Scenario 4: Streaming Dienst Toevoegen

**Situatie:** Medewerkers gebruiken een streaming dienst die niet in de standaard lijst staat. Dit veroorzaakt alerts voor onbekende bestemmingen.

**Stappen:**
1. Ga naar het **Service Providers** tabblad
2. Klik op **"Add Provider"**
3. Vul in:
   - Naam: bijv. "Interne Video Platform"
   - Categorie: "Streaming"
   - IP Ranges: de IP-reeksen van de dienst (één per regel)
   - Domains: de domeinen van de dienst (één per regel)
4. Klik op **"Create"**
5. Verkeer naar deze dienst wordt nu als normaal beschouwd

### Scenario 5: Template Genereren uit Geleerd Gedrag

**Situatie:** U heeft een nieuw IoT-apparaat aangesloten waarvan u niet precies weet welke poorten en protocollen het gebruikt.

**Stappen:**
1. Sluit het apparaat aan en laat het een paar uur draaien
2. Ga naar het **Devices** tabblad
3. Zoek het apparaat (op IP of MAC)
4. Wacht tot de Learning Status **"Ready"** toont (100+ pakketten)
5. Klik op het apparaat
6. Klik op **"Create Template from Learned Behavior"**
7. Geef de template een naam (bijv. "Slimme Thermostaat")
8. Bekijk de automatisch gegenereerde regels
9. Pas aan indien nodig (verwijder te ruime regels, voeg beschrijvingen toe)
10. De template is klaar voor gebruik en kan aan soortgelijke apparaten worden toegewezen

### Scenario 6: Built-in Template Aanpassen via Klonen

**Situatie:** De Built-in "IP Camera" template past bijna, maar uw camera's gebruiken een extra poort die niet in de standaard template zit.

**Stappen:**
1. Ga naar het **Templates** tabblad
2. Klik op de **"IP Camera"** template
3. Klik op **"Clone"**
4. Noem de kopie "IP Camera Custom"
5. Open de gekloonde template
6. Klik op **"Add Rule"** en voeg de extra poort toe
7. Ga naar **Devices** en wijs uw camera's toe aan de nieuwe template

---

## 11. Tips en Veelgestelde Vragen

### Tips voor Dagelijks Gebruik

- **Classificeer apparaten zo snel mogelijk** — Hoe sneller een apparaat een template heeft, hoe minder onnodige alerts u ontvangt
- **Begin met "Unclassified" apparaten** — Filter in het Devices tabblad op "Unclassified" om te zien welke apparaten aandacht nodig hebben
- **Gebruik templates voor groepen** — Maak één template voor alle apparaten van hetzelfde type, in plaats van elk apparaat apart te whitelisten
- **Controleer gegenereerde rules** — Als u een template genereert uit geleerd gedrag, controleer dan altijd de regels voordat u ze accepteert
- **Houd Service Providers bij** — Voeg nieuwe diensten toe als deze worden gebruikt in uw netwerk
- **Monitor de Statistics** — Houd bij hoeveel apparaten nog ongeclassificeerd zijn; streef naar zo min mogelijk

### Vermijd Deze Fouten

- **Te ruime templates** — Een template met "alle poorten allowed" is zinloos en onderdrukt álle alerts
- **Ongeclassificeerde apparaten negeren** — Deze veroorzaken de meeste onnodige alerts
- **Built-in templates wijzigen** — Dit is niet mogelijk; kloon de template als u andere regels nodig heeft
- **IP whitelist gebruiken waar een template beter past** — Een whitelist onderdrukt alle alerts; een template is nauwkeuriger
- **Suppress alert types verkeerd gebruiken** — Onderdruk alleen types waarvan u zeker weet dat ze false positives zijn

### Veelgestelde Vragen

**Vraag: Hoe lang duurt het voordat een wijziging actief is?**
Sensors synchroniseren instellingen elke 5 minuten (standaard). Na het opslaan van een wijziging kan het dus tot 5 minuten duren voordat deze actief is.

**Vraag: Kan ik een verwijderde template terugkrijgen?**
Nee, verwijderde custom templates zijn definitief verwijderd. Built-in templates kunnen niet worden verwijderd.

**Vraag: Wat gebeurt er als ik een template verwijder die aan apparaten is gekoppeld?**
Die apparaten worden "Unclassified" en kunnen weer alerts genereren voor eerder onderdrukt verkeer.

**Vraag: Worden CRITICAL alerts altijd getoond?**
C2/Threat feed alerts (communicatie met bekende malware-servers) worden **altijd** getoond, ongeacht templates of whitelists. Andere CRITICAL alerts kunnen met `suppress_alert_types` worden onderdrukt als u zeker weet dat het false positives zijn.

**Vraag: Wat is het verschil tussen "Allow" en "Suppress" als actie?**
- **Allow**: Verkeer wordt als normaal beschouwd, alerts worden onderdrukt
- **Suppress**: Alerts worden volledig verborgen (zelfde effect, andere semantiek voor rapportage)

**Vraag: Hoe weet ik welk alert type ik moet supprimeren?**
Open de alert die u wilt onderdrukken. Het alert type staat bovenaan het detail-venster (bijv. "HTTP_SENSITIVE_DATA", "UNUSUAL_PORT"). Gebruik deze naam als waarde bij het aanmaken van een suppress rule.

**Vraag: Kan ik meerdere alert types tegelijk supprimeren?**
Ja, voer meerdere types in gescheiden door komma's, bijv. `HTTP_SENSITIVE_DATA,HTTP_HIGH_ENTROPY_PAYLOAD`.

---

> **Meer informatie nodig?** Voor technische details over de parameters, database-instellingen en geavanceerde configuratie, zie de [Admin Manual](ADMIN_MANUAL.md). Voor een volledige beschrijving van de Device Classification architectuur, zie de [Device Classification documentatie](../features/DEVICE_CLASSIFICATION.md).
