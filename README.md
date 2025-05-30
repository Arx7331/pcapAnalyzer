# Pcap Anaylyzer
## pcapAnalyzer is a simple Python tool for analyzing .pcap files, providing statistics on IPs, protocols, ports, and traffic patterns to help understand network activity.


![image](https://github.com/Arx7331/pcapAnalyzer/assets/131692485/7e5e245a-73d9-4fb0-b255-6ff5ee838a86)

## 🔧 Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/Arx7331/pcapAnalyzer.git
   cd pcapAnalyze
   ```
2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
3. **Running the tool**
   ```bash
   python main.py <yourfile.pcap/pcapng>
   ```

##### Your services dictonary is on line 7-15
```python
common_services = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP",
    123: "NTP",
    25565: "Minecraft"
}
```

## Features : 
- [x] Unique IPs Counter
- [x] Most common source IP
- [x] Most common source ASN
- [x] Attack protocol percentages
- [x] TCP Flag percentages (If TCP is present in the attack)
- [x] Total traffic from the pcap (not the whole attack)
- [x] Most common Destination & Source port
- [x] Exclude ip option
- [x] Export all information to a txt
