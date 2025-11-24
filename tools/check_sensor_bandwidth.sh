#!/bin/bash
# Diagnostic script to check sensor bandwidth monitoring configuration

echo "=== Sensor Bandwidth Diagnostic ==="
echo ""

# Check network interfaces
echo "1. Available network interfaces:"
ip link show | grep -E "^[0-9]+:" | awk '{print "  -", $2}' | sed 's/:$//'
echo ""

# Check which interface is configured
echo "2. Configured monitoring interface:"
if [ -f "/home/sensor/sensor_client_config.yaml" ]; then
    grep "^interface:" /home/sensor/sensor_client_config.yaml | awk '{print "  ", $2}'
elif [ -f "sensor_client_config.yaml" ]; then
    grep "^interface:" sensor_client_config.yaml | awk '{print "  ", $2}'
else
    echo "  Config file not found"
fi
echo ""

# Check interface statistics
echo "3. Interface statistics (last 5 seconds):"
for iface in $(ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//'); do
    echo "  Interface: $iface"

    # Get RX/TX before
    rx_before=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)
    tx_before=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo 0)

    sleep 5

    # Get RX/TX after
    rx_after=$(cat /sys/class/net/$iface/statistics/rx_bytes 2>/dev/null || echo 0)
    tx_after=$(cat /sys/class/net/$iface/statistics/tx_bytes 2>/dev/null || echo 0)

    # Calculate rates (bytes per second)
    rx_rate=$(( (rx_after - rx_before) / 5 ))
    tx_rate=$(( (tx_after - tx_before) / 5 ))

    # Convert to Mbps
    rx_mbps=$(echo "scale=2; $rx_rate * 8 / 1000000" | bc)
    tx_mbps=$(echo "scale=2; $tx_rate * 8 / 1000000" | bc)

    echo "    RX: $rx_mbps Mbps"
    echo "    TX: $tx_mbps Mbps"
    echo ""
done

# Check for packet drops
echo "4. Packet drops (potential capture issues):"
for iface in $(ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//'); do
    drops=$(ip -s link show $iface | grep -A1 "RX:" | tail -1 | awk '{print $3}')
    echo "  $iface: $drops dropped packets"
done
echo ""

echo "=== Recommendations ==="
echo "- Monitoring interface should be the SPAN/mirror port (usually NOT eth0)"
echo "- Management interface (for SSH) should be separate from monitoring"
echo "- Check config.yaml and set 'interface:' to the correct monitoring interface"
echo "- If packet drops are high, consider using AF_PACKET or tcpdump instead of scapy"
