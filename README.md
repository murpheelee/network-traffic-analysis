<p align="center">
  <img src="https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white" alt="Wireshark"/>
  <img src="https://img.shields.io/badge/tcpdump-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white" alt="tcpdump"/>
  <img src="https://img.shields.io/badge/Network_Security-E4002B?style=for-the-badge" alt="NetSec"/>
</p>

# Network Traffic Analysis Lab

> **Packet capture analysis and network forensics** — analyzing malicious network traffic patterns using Wireshark and tcpdump to identify indicators of compromise, reconstruct attack timelines, and develop network-based detection signatures.

## Objective

Develop hands-on network analysis skills by examining packet captures containing real-world attack patterns. Each scenario involves capturing or analyzing network traffic, identifying malicious indicators, and documenting findings suitable for incident response reports.

## Tools & Environment

| Tool | Purpose |
|------|---------|
| Wireshark | Deep packet inspection and protocol analysis |
| tcpdump | Command-line packet capture and filtering |
| NetworkMiner | Network forensic analysis and artifact extraction |
| Azure VMs | Lab environment for generating traffic |
| Suricata | Network IDS for signature-based detection |

## Analysis Scenarios

### Scenario 1: Command & Control (C2) Beacon Detection

**Objective:** Identify periodic C2 beaconing activity hidden within normal HTTP/HTTPS traffic.

**Indicators of Compromise:**
- Regular interval HTTP POST requests (every 60 seconds ± jitter)
- Consistent payload sizes suggesting heartbeat communication
- Connections to IP addresses with no associated domain
- User-agent strings inconsistent with installed browsers

**Wireshark Filters Used:**
```
http.request.method == "POST" && ip.dst == 203.0.113.50
```

**Key Findings:**
| Indicator | Value |
|-----------|-------|
| C2 Server IP | 203.0.113.50 |
| Beacon Interval | ~60 seconds |
| Protocol | HTTP POST |
| Average Payload | 256 bytes |
| Duration | 4 hours 23 minutes |
| Total Beacons | 263 |

---

### Scenario 2: DNS Tunneling / Exfiltration

**Objective:** Detect data exfiltration through DNS queries using encoded subdomain requests.

**Indicators of Compromise:**
- Abnormally long DNS query names (50+ characters)
- High volume of TXT record queries to a single domain
- Base64-encoded subdomain labels
- DNS query frequency exceeding normal baselines

**Wireshark Filters Used:**
```
dns.qry.name contains ".exfil-domain.com" && dns.qry.type == 16
```

**Key Findings:**
| Indicator | Value |
|-----------|-------|
| Exfil Domain | data.exfil-domain.com |
| Query Type | TXT |
| Total Queries | 1,847 |
| Avg Query Length | 73 characters |
| Estimated Data Exfiltrated | ~135 KB |
| Duration | 2 hours 11 minutes |

---

### Scenario 3: ARP Spoofing / Man-in-the-Middle

**Objective:** Detect ARP spoofing attacks on a local network segment.

**Indicators of Compromise:**
- Duplicate IP-to-MAC mappings in ARP table
- Gratuitous ARP replies not matching known device inventory
- ARP storms (high volume of ARP traffic)
- Traffic redirection through unexpected MAC address

**Wireshark Filters Used:**
```
arp.duplicate-address-detected || arp.opcode == 2
```

**Key Findings:**
| Indicator | Value |
|-----------|-------|
| Attacker MAC | aa:bb:cc:dd:ee:ff |
| Spoofed IP | 10.0.0.1 (gateway) |
| Legitimate Gateway MAC | 00:11:22:33:44:55 |
| Poisoned Hosts | 12 |
| Duration | 47 minutes |

---

### Scenario 4: SMB Lateral Movement

**Objective:** Detect lateral movement via SMB/Windows file sharing between compromised hosts.

**Indicators of Compromise:**
- SMB connections from workstation-to-workstation (unusual for most environments)
- Access to administrative shares (C$, ADMIN$, IPC$)
- PsExec service installation via named pipes
- Sequential connections to multiple hosts in short timeframe

**Wireshark Filters Used:**
```
smb2.cmd == 5 && smb2.filename contains "$"
```

**Key Findings:**
| Indicator | Value |
|-----------|-------|
| Source Host | 10.0.0.105 (WS-01) |
| Targets | 10.0.0.106, .107, .108, .110 |
| Shares Accessed | ADMIN$, C$, IPC$ |
| Method | PsExec via named pipe (PSEXESVC) |
| Time Span | 8 minutes |

---

### Scenario 5: Brute Force Attack (RDP)

**Objective:** Identify RDP brute force attempts from external IP against a public-facing server.

**Indicators of Compromise:**
- High volume of TCP SYN packets to port 3389 from single source
- Repeated TLS handshake failures
- Connection attempts at regular intervals suggesting automated tool

**tcpdump Filter Used:**
```bash
tcpdump -r capture.pcap 'tcp dst port 3389 and tcp[tcpflags] & (tcp-syn) != 0' | awk '{print $3}' | sort | uniq -c | sort -rn | head 10
```

**Key Findings:**
| Indicator | Value |
|-----------|-------|
| Attacker IP | 198.51.100.22 |
| Target | 10.0.0.50:3389 |
| Total Attempts | 4,721 |
| Duration | 6 hours 14 minutes |
| Rate | ~12.6 attempts/minute |
| Successful Auth | 1 (at attempt #3,847) |

---

## Network Detection Signatures

### Suricata Rules Developed

```
# C2 Beacon Detection (HTTP POST to known C2)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible C2 Beacon - Regular POST Interval"; flow:established,to_server; content:"POST"; http_method; threshold:type both, track by_src, count 10, seconds 600; classtype:trojan-activity; sid:1000001; rev:1;)

# DNS Tunneling Detection (Long DNS queries)
alert dns $HOME_NET any -> any 53 (msg:"Possible DNS Tunneling - Abnormally Long Query"; dns.query; content:"."; pcre:"/^[a-zA-Z0-9]{50,}\./"; classtype:bad-unknown; sid:1000002; rev:1;)

# SMB Lateral Movement (Admin share access)
alert smb any any -> $HOME_NET 445 (msg:"SMB Admin Share Access - Possible Lateral Movement"; content:"|00|A|00|D|00|M|00|I|00|N|00|$|00|"; classtype:attempted-admin; sid:1000003; rev:1;)
```

## Key Skills Demonstrated

- Deep packet inspection with Wireshark and tcpdump
- Network forensics and attack reconstruction
- C2 traffic pattern identification
- DNS tunneling and data exfiltration detection
- ARP spoofing and MITM attack detection
- Lateral movement analysis via SMB
- Network IDS signature development (Suricata)
- Incident response reporting and documentation
