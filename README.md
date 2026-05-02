# uefi-netstack

# IT SUPPORTS ONLY ETHERNET AND YOU NEED EDK2 TO COMPILE IT

**A complete bare-metal IPv4 network stack for UEFI applications.**

Built entirely from scratch using only the `EFI_SIMPLE_NETWORK_PROTOCOL` — no OS, no runtime, no external libraries. Just raw Ethernet frames and hand-crafted protocol implementations.

---

## Features

| Protocol | Implementation |
|----------|---------------|
| **DHCP** | Full handshake (Discover → Offer → Request → ACK) with option parsing |
| **ARP**  | Request/Reply + automatic cache (8 entries, round-robin eviction) |
| **DNS**  | A-record queries with name compression support |
| **TCP**  | 3-way handshake, data transfer, graceful close (FIN), RST handling |
| **UDP**  | Send/Receive with ephemeral port allocation |
| **ICMP** | Echo Request/Reply (ping) — both outgoing and incoming |
| **HTTP** | Simple HTTP/1.1 GET client with `Host` header |

### Additional Capabilities

- **Static IP configuration** — bypass DHCP with `init_network_static()`
- **ARP cache** — avoids redundant ARP requests for recently resolved IPs
- **PRNG** — seeded from EFI Real-Time Clock for randomised transaction IDs and ports
- **Zero dependencies** — no CRT, no libc, no EDK2 library binaries (headers only)

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  api.hpp                         │
│  init_network() | tcp_*() | udp_*() | ping()    │
│  http_get() | resolve_hostname()                 │
├──────────────────────────────────────────────────┤
│            protocols.hpp          core.hpp        │
│  DHCP builder | ARP builder │ Packet dispatcher  │
│  DNS builder                │ TCP state machine  │
│                             │ ICMP handler        │
│                             │ UDP send            │
├──────────────────────────────────────────────────┤
│   types.hpp  │  net_math.hpp  │  arp_cache.hpp   │
│   Packed     │  IP/TCP/UDP    │  IP→MAC lookup    │
│   headers    │  checksums     │                   │
├──────────────────────────────────────────────────┤
│   constants.hpp │ globals.hpp │ memory.hpp        │
│   Named values  │ State vars  │ memcpy/memset     │
│   utils.hpp     │ rng.hpp     │ io.hpp            │
│   Byte order    │ PRNG        │ Console output    │
├──────────────────────────────────────────────────┤
│          EFI_SIMPLE_NETWORK_PROTOCOL             │
│              (Firmware / NIC driver)              │
└──────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Build

**Requirements:**
- Visual Studio 2019+ with C++ Desktop workload
- Windows Driver Kit (WDK) 10
- [EDK2 headers](https://github.com/tianocore/edk2) (only `MdePkg/Include` is needed)

```
1. Clone EDK2 next to this project (or adjust include paths in .vcxproj)
2. Open bootx64.sln in Visual Studio
3. Select Release | x64
4. Build → Build Solution
5. Output: x64/Release/bootx64.efi
```

### 2. Deploy

Create a bootable USB drive:

```
1. Format a USB drive as FAT32
2. Create directory:  \EFI\BOOT\
3. Copy bootx64.efi → \EFI\BOOT\BOOTX64.EFI
4. Boot from USB (UEFI mode, Secure Boot disabled)
```

### 3. Run

The application will:
1. Obtain an IP address via DHCP
2. Display network configuration (MAC, IP, subnet, gateway, DNS)
3. Ping the default gateway
4. Resolve `example.com` via DNS
5. Fetch `http://example.com/` and display the response

---

## API Reference

### Network Initialization

```cpp
// Initialize via DHCP (auto-configure everything)
EFI_STATUS api::init_network();

// Initialize with static IP (no DHCP)
EFI_STATUS api::init_network_static(
    UINT32 ip,       // Your IP address (network byte order)
    UINT32 gateway,  // Default gateway
    UINT32 mask,     // Subnet mask
    UINT32 dns       // DNS server (0 = use Google 8.8.8.8)
);
```

### DNS

```cpp
// Resolve a hostname to an IPv4 address
EFI_STATUS api::resolve_hostname(
    const CHAR8* hostname,  // e.g. "example.com"
    UINT32* out_ip          // Result (network byte order)
);
```

### TCP

```cpp
EFI_STATUS api::tcp_connect(UINT32 ip, UINT16 port);
EFI_STATUS api::tcp_send(const VOID* data, UINTN len);
EFI_STATUS api::tcp_receive(VOID* buffer, UINTN max_len, UINTN* actual_len, UINT32 timeout_ms);
EFI_STATUS api::tcp_close();
```

### UDP

```cpp
EFI_STATUS api::udp_send(UINT32 dest_ip, UINT16 dest_port, const VOID* data, UINTN len);
EFI_STATUS api::udp_receive(VOID* buffer, UINTN max_len, UINTN* actual_len, UINT32 timeout_ms);
```

### ICMP

```cpp
// Ping an IP and wait for reply
EFI_STATUS api::ping(UINT32 target_ip, UINT32 timeout_ms);
```

### HTTP

```cpp
// Simple HTTP/1.1 GET request
EFI_STATUS api::http_get(
    const CHAR8* hostname,       // Server hostname
    const CHAR8* path,           // Request path (e.g. "/")
    VOID* response_buffer,       // Output buffer
    UINTN max_len,               // Buffer size
    UINTN* actual_len            // Bytes received
);
```

### Utilities

```cpp
UINT32 utils::make_ipv4(UINT8 a, UINT8 b, UINT8 c, UINT8 d);  // Build IP from octets
io::print_ip(UINT32 ip);            // Print dotted-decimal IP
io::print_mac(const UINT8* mac);    // Print XX:XX:XX:XX:XX:XX
io::print_hex(UINT64 val);          // Print 0xHEX
io::print_dec(UINT64 val);          // Print decimal
```

---

## Examples

| Example | Description |
|---------|-------------|
| [`example_http_get.cpp`](examples/example_http_get.cpp) | Fetch a webpage via HTTP GET |
| [`example_ping.cpp`](examples/example_ping.cpp) | ICMP ping the default gateway |
| [`example_dns_lookup.cpp`](examples/example_dns_lookup.cpp) | Resolve multiple hostnames |
| [`example_tcp_client.cpp`](examples/example_tcp_client.cpp) | Raw TCP connect/send/receive |
| [`example_udp_echo.cpp`](examples/example_udp_echo.cpp) | UDP send/receive datagrams |
| [`example_static_ip.cpp`](examples/example_static_ip.cpp) | Static IP configuration (no DHCP) |

Each example is a standalone `EfiMain()` entry point with full comments.

---

## Project Structure

```
bootx64/
├── main.cpp              # Entry point — full feature demo
├── constants.hpp         # All protocol constants & enums
├── types.hpp             # Packed network header structs
├── globals.hpp           # Global state variables
├── memory.hpp            # Freestanding memset/memcpy
├── utils.hpp             # Byte order + string utilities
├── rng.hpp               # PRNG from EFI Real-Time Clock
├── net_math.hpp          # IP/TCP/UDP checksum (RFC 1071)
├── io.hpp                # Console output helpers
├── arp_cache.hpp         # Simple IP → MAC cache
├── icmp.hpp              # ICMP echo request/reply
├── protocols.hpp         # DHCP, ARP, DNS packet builders
├── core.hpp              # Packet dispatcher + TCP state machine
├── api.hpp               # Public API (all user-facing functions)
├── examples/             # Standalone example programs
├── bootx64.sln           # Visual Studio solution
├── bootx64.vcxproj       # Project file
├── LICENSE               # MIT License
└── .gitignore            # Build artifact exclusions
```

---

## Limitations

This is a **minimal educational implementation**. The following features are intentionally omitted:

- **TLS/HTTPS** — No encryption support
- **IPv6** — IPv4 only
- **TCP retransmission** — Lost packets are not retransmitted
- **TCP window scaling** — Fixed 8KB window
- **IP fragmentation** — Oversized packets are not reassembled
- **Multi-connection** — Only one TCP session at a time
- **DHCP renewal** — Lease is not renewed after expiration
- **VLAN tagging** — 802.1Q not supported
- **Checksum offload** — All checksums computed in software

---

## How It Works

### Boot Sequence
1. UEFI firmware loads `BOOTX64.EFI` from the ESP partition
2. `EfiMain()` receives the System Table with Boot/Runtime Services
3. We locate `EFI_SIMPLE_NETWORK_PROTOCOL` — the NIC's raw frame interface
4. Start/Initialize the NIC and configure receive filters

### Network Initialization (DHCP)
1. Send DHCP Discover (broadcast UDP to 255.255.255.255:67)
2. Receive DHCP Offer — extract offered IP, server IP, gateway, DNS, subnet
3. Send DHCP Request — confirm the offered IP
4. Receive DHCP ACK — IP is now ours
5. Send ARP Request for the default gateway to learn its MAC address
6. Network is ready — we can send/receive IP packets

### Packet Flow
- **Outgoing**: API → build headers (eth/ip/tcp|udp) → `core::send_raw()` → SNP->Transmit
- **Incoming**: SNP->Receive → `core::poll()` → dispatch by EtherType → protocol handler

---

## Contributing

Contributions are welcome! Some areas that would benefit from improvement:

- [ ] TCP retransmission with exponential backoff
- [ ] TCP window scaling (RFC 7323)
- [ ] IP fragmentation reassembly
- [ ] DHCP lease renewal
- [ ] Multiple simultaneous TCP connections
- [ ] DNS CNAME/AAAA record support
- [ ] Basic TLS 1.2 handshake

---

## License

This project is licensed under the [MIT License](LICENSE).

## Expected output

```
========================================================
  UEFI Bare-Metal Network Stack v1.0
  IA made but it works i think...
========================================================

[*] Initializing network (DHCP)...
[+] Network initialized successfully!

--- Network Configuration ---
  MAC Address : 00:0C:29:E2:DC:4A
  IP Address  : 192.168.161.128
  Subnet Mask : 255.255.255.0
  Gateway     : 192.168.161.2
  DNS Server  : 192.168.161.2
  Lease Time  : 1800 seconds
-----------------------------

[*] Pinging gateway (192.168.161.2)...
[+] Ping reply received!

[*] Resolving example.com...
[+] example.com -> 104.20.23.154

[*] Fetching http://example.com/ ...

--- HTTP Response (832 bytes) ---
HTTP/1.1 200 OK
Date: Sat, 02 May 2026 02:06:09 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: close
Server: cloudflare
Last-Modified: Fri, 01 May 2026 01:24:29 GMT
Allow: GET, HEAD
Accept-Ranges: bytes
Age: 3192
cf-cache-status: HIT
CF-RAY: 9f537710597ef8f1-NVT

210
<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style></head><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.</p><p><a href="https://iana.org/domains/example">Learn more</a></p></div></body></html>


--- End of Response ---

[*] Demo complete. Press reset to reboot.
```
