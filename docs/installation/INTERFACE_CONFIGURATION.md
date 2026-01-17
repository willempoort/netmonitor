# Network Interface Configuration - Important Information

## ⚠️ CRITICAL: Interface Selection is Required

### Overview
The network interface selection in the sensor settings **directly determines which network traffic is monitored**. If no interfaces are selected, the sensor **cannot capture any network traffic** and will not generate:

- ❌ Network traffic metrics
- ❌ Alerts and threat detections
- ❌ Top talkers data
- ❌ Bandwidth statistics
- ❌ PCAP forensics captures

**The sensor will appear online but will not collect any monitoring data!**

---

## Configuring Network Interfaces

### Dashboard Configuration

1. Navigate to **Dashboard → Sensors**
2. Click the **⚙️ (gear icon)** on the sensor you want to configure
3. In the **Network Interface(s)** section:
   - **Select at least ONE interface** (required)
   - You can select multiple interfaces for monitoring
   - Each interface shows its status:
     - 🟢 **PROMISC** (green) = Promiscuous mode enabled (recommended)
     - 🔴 **NOT PROMISC** (red) = Normal mode (may miss some traffic)
     - ⚪ **unknown** = Status not yet reported

4. Click **Save Settings**

### Validation

The dashboard will **prevent saving** if no interfaces are selected and show:

```
⚠️ ERROR: You must select at least one network interface!

The sensor cannot monitor network traffic without an interface.
Please select one or more interfaces before saving.
```

---

## Interface Options

### Single Interface
Select one specific interface (e.g., `ens192`)
- **Use case**: Monitor traffic on a specific network segment
- **Example**: `ens192` for production network monitoring

### Multiple Interfaces
Select multiple interfaces (e.g., `ens192`, `ens224`)
- **Use case**: Monitor multiple network segments simultaneously
- **Example**: `ens192,ens224` for multi-segment monitoring
- **Note**: Requires sufficient CPU/memory resources

### All Interfaces
Select the **"All Interfaces"** checkbox
- **Use case**: Monitor all network traffic on the system
- **Warning**: May generate high CPU load and storage usage
- **Recommended**: Only for dedicated sensor appliances

---

## Promiscuous Mode

### What is Promiscuous Mode?

Promiscuous mode allows a network interface to capture **all network packets**, not just packets addressed to the interface itself.

### Why is it Important?

- **✅ WITH PROMISC**: Captures all traffic on the network segment (full visibility)
- **❌ WITHOUT PROMISC**: Only captures traffic to/from the sensor's IP (limited visibility)

### Enabling Promiscuous Mode

The sensor **automatically enables** promiscuous mode on selected interfaces when started.

Check status:
```bash
ip link show ens192
```

Look for `PROMISC` flag:
```
2: ens192: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500
```

Manual enable (if needed):
```bash
sudo ip link set ens192 promisc on
```

---

## Mirror Port / SPAN Configuration

For **optimal monitoring**, especially in switched environments:

### Recommended Setup

1. **Configure a mirror/SPAN port** on your network switch
2. **Connect the sensor** to the mirror port
3. **Select the mirrored interface** in the dashboard
4. **Enable promiscuous mode** (automatic)

### Benefits

- Captures **all network traffic** passing through the switch
- **No inline deployment** required (passive monitoring)
- **No performance impact** on production traffic
- **Full visibility** of internal network communications

### Example: Cisco Switch Configuration

```
! Configure SPAN session
monitor session 1 source interface Gi1/0/1 - 24 both
monitor session 1 destination interface Gi1/0/48

! Sensor connects to Gi1/0/48 (ens192)
! Dashboard: Select "ens192"
```

---

## Troubleshooting

### Sensor Online but No Data

**Symptoms:**
- Sensor shows as "online" in dashboard
- No traffic metrics, alerts, or top talkers
- Last seen updates regularly

**Solution:**
1. Check interface configuration:
   ```bash
   # On sensor
   grep interface /etc/netmonitor/sensor.yaml
   ```

2. Verify interface selection in dashboard:
   - Open sensor settings
   - Confirm at least one interface is checked
   - Save if needed

3. Check sensor logs:
   ```bash
   sudo journalctl -u netmonitor-sensor -f
   ```

   Look for:
   ```
   Monitoring interface: ens192
   ```

4. Restart sensor to apply changes:
   ```bash
   sudo systemctl restart netmonitor-sensor
   ```

### Interface Not Listed

**Symptoms:**
- Expected interface doesn't appear in dropdown

**Solution:**
1. Verify interface exists on sensor:
   ```bash
   ip link show
   ```

2. Check sensor registration:
   ```bash
   # On SOC server
   psql -U netmonitor -d netmonitor -c \
     "SELECT sensor_id, config->>'available_interfaces' FROM sensors;"
   ```

3. Re-register sensor (updates interface list):
   ```bash
   # On sensor
   sudo systemctl restart netmonitor-sensor
   ```

---

## Best Practices

### ✅ DO:
- **Always select at least one interface**
- **Use mirror/SPAN ports** for switched environments
- **Enable promiscuous mode** for full visibility
- **Monitor production interfaces** (where actual traffic flows)
- **Document your interface selections** in sensor location field

### ❌ DON'T:
- **Never leave interfaces unselected** (sensor won't monitor!)
- **Avoid monitoring loopback** (lo) - no useful traffic
- **Don't select all interfaces** on production servers (high load)
- **Don't forget to save** after making changes

---

## Configuration Changes

### When Configuration Changes

After changing interface selection in the dashboard:

1. **Automatic**: Sensor pulls new config within 5 minutes (config_sync_interval)
2. **Manual**: Restart sensor immediately:
   ```bash
   sudo systemctl restart netmonitor-sensor
   ```

3. **Verification**: Check logs for confirmation:
   ```bash
   sudo journalctl -u netmonitor-sensor | grep "Monitoring interface"
   ```

### Sensor Restart Required

⚠️ **Changing interfaces requires sensor restart** to take effect!

The dashboard shows a reminder:
> ⚠️ Sensor restart required after change

---

## Summary

| Configuration | Impact | Recommendation |
|--------------|--------|----------------|
| **No interfaces selected** | ❌ **NO MONITORING** | Never do this! |
| **Single interface** | ✅ Monitors one segment | Good for most setups |
| **Multiple interfaces** | ✅ Monitors multiple segments | Requires more resources |
| **All interfaces** | ⚠️ High load | Only for dedicated sensors |
| **Promiscuous mode OFF** | ⚠️ Limited visibility | Always enable PROMISC |
| **Mirror/SPAN port** | ✅✅ Best visibility | Recommended for production |

---

## Contact

For questions or issues related to interface configuration:
- **GitHub Issues**: https://github.com/willempoort/netmonitor/issues
- **Documentation**: See main README.md

---

**Version**: 1.0.0
**Last Updated**: 2026-01-17
