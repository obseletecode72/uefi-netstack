#pragma once

/**
 * @file types.hpp
 * @brief Packed C structures for all network protocol headers.
 *
 * Every structure is byte-aligned (#pragma pack(1)) to match on-the-wire
 * layout exactly. Fields are stored in network byte order unless the code
 * explicitly converts them with utils::htons / utils::htonl.
 *
 * Supported headers:
 *  - Ethernet II (eth_hdr)
 *  - ARP        (arp_hdr)
 *  - IPv4       (ip_hdr)
 *  - ICMP       (icmp_hdr)
 *  - UDP        (udp_hdr)
 *  - TCP        (tcp_hdr)
 *  - DHCP       (dhcp_hdr)
 *  - DNS        (dns_hdr)
 *  - IPv4 pseudo-header for checksum (pseudo_hdr)
 */

#pragma pack(push, 1)
namespace types
{
    /// @brief Ethernet II frame header (14 bytes).
    typedef struct
    {
        UINT8  dst[0x06];       ///< Destination MAC address
        UINT8  src[0x06];       ///< Source MAC address
        UINT16 type;            ///< EtherType (e.g. 0x0800 = IPv4, 0x0806 = ARP)
    } eth_hdr;

    /// @brief ARP header for Ethernet/IPv4 (28 bytes).
    typedef struct
    {
        UINT16 htype;           ///< Hardware type (1 = Ethernet)
        UINT16 ptype;           ///< Protocol type (0x0800 = IPv4)
        UINT8  hlen;            ///< Hardware address length (6)
        UINT8  plen;            ///< Protocol address length (4)
        UINT16 oper;            ///< Operation (1 = request, 2 = reply)
        UINT8  sha[0x06];       ///< Sender hardware address
        UINT32 spa;             ///< Sender protocol address
        UINT8  tha[0x06];       ///< Target hardware address
        UINT32 tpa;             ///< Target protocol address
    } arp_hdr;

    /// @brief IPv4 header (20 bytes, no options).
    typedef struct
    {
        UINT8  ihl_version;     ///< Version (4 bits) + IHL (4 bits)
        UINT8  tos;             ///< Type of service / DSCP + ECN
        UINT16 tot_len;         ///< Total length (header + payload)
        UINT16 id;              ///< Identification (for fragmentation)
        UINT16 frag_off;        ///< Flags (3 bits) + Fragment offset (13 bits)
        UINT8  ttl;             ///< Time to live
        UINT8  protocol;        ///< Upper-layer protocol (6 = TCP, 17 = UDP, 1 = ICMP)
        UINT16 check;           ///< Header checksum
        UINT32 saddr;           ///< Source IP address
        UINT32 daddr;           ///< Destination IP address
    } ip_hdr;

    /// @brief ICMP header (8 bytes, followed by payload).
    typedef struct
    {
        UINT8  type;            ///< Message type (8 = echo request, 0 = echo reply)
        UINT8  code;            ///< Message code
        UINT16 checksum;        ///< ICMP checksum
        UINT16 id;              ///< Identifier (for matching request/reply)
        UINT16 seq;             ///< Sequence number
    } icmp_hdr;

    /// @brief UDP header (8 bytes).
    typedef struct
    {
        UINT16 source;          ///< Source port
        UINT16 dest;            ///< Destination port
        UINT16 len;             ///< Length (header + payload)
        UINT16 check;           ///< Checksum (optional for IPv4, 0 = disabled)
    } udp_hdr;

    /// @brief DHCP message (variable-length, options follow the magic cookie).
    typedef struct
    {
        UINT8  op;              ///< Message op code (1 = request, 2 = reply)
        UINT8  htype;           ///< Hardware address type (1 = Ethernet)
        UINT8  hlen;            ///< Hardware address length (6)
        UINT8  hops;            ///< Hops (relay agents)
        UINT32 xid;             ///< Transaction ID
        UINT16 secs;            ///< Seconds elapsed
        UINT16 flags;           ///< Flags (0x8000 = broadcast)
        UINT32 ciaddr;          ///< Client IP address
        UINT32 yiaddr;          ///< 'Your' (client) IP address
        UINT32 siaddr;          ///< Next server IP address
        UINT32 giaddr;          ///< Relay agent IP address
        UINT8  chaddr[0x10];    ///< Client hardware address (16 bytes, padded)
        UINT8  sname[0x40];     ///< Server host name (64 bytes)
        UINT8  file[0x80];      ///< Boot file name (128 bytes)
        UINT32 magic;           ///< Magic cookie (0x63825363)
        UINT8  options[0x12C];  ///< DHCP options (variable, up to 300 bytes)
    } dhcp_hdr;

    /// @brief TCP header (20 bytes, no options).
    typedef struct
    {
        UINT16 source;          ///< Source port
        UINT16 dest;            ///< Destination port
        UINT32 seq;             ///< Sequence number
        UINT32 ack_seq;         ///< Acknowledgment number
        UINT16 res1_doff_flags; ///< Data offset (4 bits), reserved (6 bits), flags (6 bits)
        UINT16 window;          ///< Window size
        UINT16 check;           ///< Checksum
        UINT16 urg_ptr;         ///< Urgent pointer
    } tcp_hdr;

    /// @brief IPv4 pseudo-header used for TCP/UDP checksum calculation (12 bytes).
    typedef struct
    {
        UINT32 saddr;           ///< Source IP address
        UINT32 daddr;           ///< Destination IP address
        UINT8  zero;            ///< Reserved (zero)
        UINT8  protocol;        ///< Protocol (6 = TCP, 17 = UDP)
        UINT16 tcp_length;      ///< TCP/UDP segment length (header + data)
    } pseudo_hdr;

    /// @brief DNS message header (12 bytes, followed by queries/answers).
    typedef struct
    {
        UINT16 id;              ///< Transaction ID
        UINT16 flags;           ///< Flags (QR, Opcode, AA, TC, RD, RA, RCODE)
        UINT16 qdcount;         ///< Number of questions
        UINT16 ancount;         ///< Number of answer RRs
        UINT16 nscount;         ///< Number of authority RRs
        UINT16 arcount;         ///< Number of additional RRs
    } dns_hdr;
}
#pragma pack(pop)
