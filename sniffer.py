from scapy.all import sniff, IP, TCP, UDP, ICMP  # Import packet capture and protocol layers from Scapy
from datetime import datetime  # Import datetime to timestamp each captured packet

LOG_FILE = "packets.txt"  # File where captured packets will be saved
REPORT_FILE = "report.html"  # File where the HTML report will be saved
packet_count = 0  # Counter to track total packets captured
packets_data = []  # List to store packet info for the report

def process_packet(packet):
    global packet_count

    # Only process packets that have an IP layer (filters out non-IP traffic)
    if IP in packet:
        src_ip = packet[IP].src  # Extract the source IP address
        dst_ip = packet[IP].dst  # Extract the destination IP address
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp
        protocol = "OTHER"  # Default protocol if none matched below
        info = ""  # Default info string for port details

        # Determine the protocol and extract port information
        if TCP in packet:
            protocol = "TCP"
            info = f"Port {packet[TCP].sport} -> {packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            info = f"Port {packet[UDP].sport} -> {packet[UDP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"  # ICMP does not use ports (used by ping)

        # Apply protocol filter — skip packet if it doesn't match the selected filter
        if selected_filter != "ALL" and protocol != selected_filter:
            return

        # Increment the packet counter
        packet_count += 1

        # Format the log entry with timestamp, protocol, IPs, and port info
        log = f"[{timestamp}] {protocol} | {src_ip} -> {dst_ip} | {info}"
        print(log)  # Print packet info to the terminal in real time

        # Store packet data for the HTML report
        packets_data.append({
            "timestamp": timestamp,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "info": info
        })

        # Append the log entry to the log file
        with open(LOG_FILE, "a") as f:
            f.write(log + "\n")

def generate_report():
    # Count packets by protocol for the summary
    tcp_count = sum(1 for p in packets_data if p["protocol"] == "TCP")
    udp_count = sum(1 for p in packets_data if p["protocol"] == "UDP")
    icmp_count = sum(1 for p in packets_data if p["protocol"] == "ICMP")
    other_count = sum(1 for p in packets_data if p["protocol"] == "OTHER")

    # Build the HTML report
    rows = ""
    for p in packets_data:
        # Color code rows by protocol
        color = {"TCP": "#e8d0ff", "UDP": "#d4f4dd", "ICMP": "#fff3cd", "OTHER": "#f0f0f0"}.get(p["protocol"], "#ffffff")
        rows += f"""
        <tr style="background-color: {color};">
            <td>{p['timestamp']}</td>
            <td>{p['protocol']}</td>
            <td>{p['src_ip']}</td>
            <td>{p['dst_ip']}</td>
            <td>{p['info']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Packet Sniffer Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; color: #333; }}
        h1 {{ color: #5b2d8e; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; min-width: 120px; text-align: center; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
        .card h2 {{ margin: 0; font-size: 2em; color: #5b2d8e; }}
        .card p {{ margin: 5px 0 0; color: #777; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }}
        th {{ background: #5b2d8e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
        tr:last-child td {{ border-bottom: none; }}
    </style>
</head>
<body>
    <h1>Packet Sniffer Report</h1>
    <p>Filter: <strong>{selected_filter}</strong> | Generated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong></p>
    <div class="summary">
        <div class="card"><h2>{packet_count}</h2><p>Total</p></div>
        <div class="card"><h2>{tcp_count}</h2><p>TCP</p></div>
        <div class="card"><h2>{udp_count}</h2><p>UDP</p></div>
        <div class="card"><h2>{icmp_count}</h2><p>ICMP</p></div>
        <div class="card"><h2>{other_count}</h2><p>Other</p></div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Protocol</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Port Info</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""

    with open(REPORT_FILE, "w") as f:
        f.write(html)

    print(f"Report saved to {REPORT_FILE}, open it in your browser! :)")

# Ask the user which protocol to filter by
print("Select a filter:")
print("  1. ALL")
print("  2. TCP")
print("  3. UDP")
print("  4. ICMP")

choice = input("Enter choice (1-4): ").strip()

# Map user choice to protocol name
filter_map = {"1": "ALL", "2": "TCP", "3": "UDP", "4": "ICMP"}
selected_filter = filter_map.get(choice, "ALL")  # Default to ALL if invalid input

print(f"\nFilter set to: {selected_filter}")
print("Starting packet sniffer... Press CTRL+C to stop.")
print(f"Logging packets to {LOG_FILE}\n")

try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    pass
finally:
    print(f"\nSniffer stopped.")
    print(f"Total packets captured: {packet_count}")
    generate_report()