# Pattern Rules (detectieregels uit de database)

Sinds v2.9.0 kun je nieuwe aanvalspatronen toevoegen **zonder de broncode aan te passen**.
Een patroonregel staat in de tabel `detection_rules` en wordt uitgevoerd door `rule_engine.py`,
op de SOC-server en op alle sensors (v2.9.0+).

Beheer: **dashboard > Pattern Rules**. Alleen admins kunnen regels toevoegen, wijzigen of uitzetten;
operators kunnen ze bekijken. Elke wijziging komt in het audit-log (`web_user_audit`).

## Hoe het werkt

- Een regel is **declaratief**: een vaste set velden. Er wordt nooit code uit de database uitgevoerd.
- Alle velden in `match` moeten kloppen (EN). Binnen een lijst is één waarde genoeg (OF).
- De IP-whitelist geldt ook voor regels. De onderdrukking via apparaattemplates geldt **niet**:
  een regel is een bewuste keuze.
- De SOC-server ververst de regels elke 60 s uit de database
  (`thresholds.detection_rules.refresh_interval`). Sensors vragen elke 60 s of er iets gewijzigd is
  (`performance.rules_sync_interval`) en downloaden de regels alleen bij een wijziging.
- Uitzetten van de hele engine: `thresholds.detection_rules.enabled: false`.

## Velden

| Groep | Veld | Voorbeeld |
|---|---|---|
| Pakket | `protocol` | `"tcp"`, `"udp"`, `"icmp"` |
| | `direction` | `"inbound"` (extern → intern), `"outbound"`, `"internal"` |
| | `src_cidr`, `dst_cidr` | `["1.1.1.1/32", "10.0.0.0/8"]` |
| | `src_port`, `dst_port` | `"80,443,8000-8100"` |
| | `new_connection` | `true` = alleen TCP SYN (telt verbindingen i.p.v. pakketten) |
| Inhoud | `payload_contains` | `["cmd.exe", "/bin/sh"]` |
| | `payload_regex` | `"wget\\s+http"` |
| | `payload_hex_prefix` | `"01000000"` |
| | `payload_size` | `"148"` of `"100-200"` (bytes L4-payload) |
| | `nocase` | standaard `true` |
| HTTP (elke poort) | `http_method` | `["POST"]` |
| | `http_uri_contains`, `http_uri_regex` | `["/cgi-bin/"]`, `"\\.\\./"` |
| | `http_host_regex`, `http_user_agent_regex`, `http_header_regex` | |
| DNS-query | `dns_qname_suffix` | `["eth"]` (matcht `x.eth`, niet `zeth`) |
| | `dns_qname_regex`, `dns_qtype` | `["TXT"]` |
| TLS ClientHello | `tls_sni_suffix`, `tls_sni_regex`, `ja3` | `["cloudflare-dns.com"]` |
| Apparaat | `device_class` | `["iot"]`; ook `server`, `endpoint`, `infrastructure`, `other`, `unclassified` |
| | `device_class_of` | `"src"` (standaard) of `"dst"` |

Een regel combineert DNS-, TLS- en HTTP-velden niet met elkaar. Een regel met alleen
`protocol`/`direction` wordt geweigerd (te breed).

Daarnaast per regel: `threshold_count` binnen `threshold_window` seconden (standaard 1 binnen 60 s),
`cooldown` (stilte na een melding, standaard 300 s), `track_by` (`src`, `dst` of `pair`),
`severity`, `alert_type` (standaard `DETECTION_RULE`), `cve` en `reference_url`.

## Voorbeeld: CVE-signatuur

```json
{
  "protocol": "tcp",
  "dst_port": "32400",
  "direction": "inbound",
  "http_method": ["GET", "POST"],
  "http_uri_regex": "\\.\\./|%2e%2e"
}
```

Gebruik signaturen uit een betrouwbare bron (advisory, Emerging Threats-regel) en zet de bron in
`reference_url`.

## Prestaties en veiligheid

- Regels worden één keer gecompileerd en geïndexeerd op protocol en doelpoort. DNS-, TLS- en
  HTTP-regels worden alleen bekeken bij een DNS-query, TLS ClientHello of HTTP-request.
- Tientallen tot een paar honderd regels zijn geen probleem. Voor duizenden CVE-signaturen is
  Suricata met een Emerging Threats-ruleset geschikter.
- Payload wordt maximaal 4 KB doorzocht. Regexes met geneste kwantoren (`(a+)+`) of
  backreferences worden geweigerd, ter bescherming tegen ReDoS.

## Standaardregels

Bij een schema-update worden ontbrekende standaardregels (`builtin.*`) toegevoegd. Je kunt ze
aanpassen of uitzetten, maar niet verwijderen; aangepaste standaardregels worden niet overschreven.

| Regel | Patroon |
|---|---|
| `builtin.doh-from-iot`, `builtin.doh-ip-from-iot` | IoT-apparaat gebruikt DNS-over-HTTPS (JackSkid/AISURU) |
| `builtin.dns-txt-burst-iot` | ≥10 TXT-opvragingen in 10 min vanaf IoT (AISURU, TuxBot v3) |
| `builtin.ens-blockchain-c2` | `.eth`-domeinen (Dysphoria) |
| `builtin.eth-rpc-from-device` | Ethereum-RPC vanaf IoT/infrastructuur/servers |
| `builtin.dead-drop-from-iot` | Telegram/Pastebin e.d. vanaf IoT/infrastructuur |
| `builtin.wireguard-handshake-out`, `builtin.openvpn-out` | Uitgaande VPN-tunnels (CISA AA26-281A) |
| `builtin.remote-access-tool` | AnyDesk, RustDesk, ScreenConnect, Tailscale, ZeroTier, ngrok, Cloudflare-tunnels |

## API

| Methode | Pad | Rol |
|---|---|---|
| GET | `/api/detection-rules` | admin, operator |
| POST | `/api/detection-rules` | admin |
| PUT / DELETE | `/api/detection-rules/<id>` | admin |
| POST | `/api/detection-rules/<id>/enabled` (`{"enabled": false}`) | admin |
| POST | `/api/detection-rules/validate` | admin |
| GET | `/api/detection-rules/sync?version=<hash>` | sensortoken of login |
