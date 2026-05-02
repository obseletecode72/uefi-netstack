#pragma once

/**
 * @file constants.hpp
 * @brief Central repository for all protocol constants, flag definitions,
 *        timeout values, and state machine enumerations used by the network stack.
 *
 * Eliminates magic numbers from the codebase and serves as a single source of
 * truth for every numeric literal that carries protocol-level meaning.
 */

namespace constants
{
    // =========================================================================
    //  Ethernet (IEEE 802.3)
    // =========================================================================

    constexpr UINT16 ETHERTYPE_IPV4         = 0x0800;   ///< IPv4 datagram
    constexpr UINT16 ETHERTYPE_ARP          = 0x0806;   ///< ARP frame
    constexpr UINTN  ETH_ALEN              = 0x06;      ///< MAC address length in bytes

    // =========================================================================
    //  IPv4 (RFC 791)
    // =========================================================================

    constexpr UINT8  IP_VERSION_IHL_DEFAULT = 0x45;      ///< IPv4, 20-byte header (IHL = 5)
    constexpr UINT8  IP_PROTO_ICMP          = 0x01;      ///< ICMP protocol number
    constexpr UINT8  IP_PROTO_TCP           = 0x06;      ///< TCP protocol number
    constexpr UINT8  IP_PROTO_UDP           = 0x11;      ///< UDP protocol number
    constexpr UINT8  IP_DEFAULT_TTL         = 0x40;      ///< Default Time-To-Live (64)
    constexpr UINTN  IP_HDR_MIN_LEN         = 0x14;      ///< Minimum IP header length (20)

    // =========================================================================
    //  ARP (RFC 826)
    // =========================================================================

    constexpr UINT16 ARP_HTYPE_ETHERNET     = 0x0001;    ///< Hardware type: Ethernet
    constexpr UINT16 ARP_PTYPE_IPV4         = 0x0800;    ///< Protocol type: IPv4
    constexpr UINT8  ARP_HLEN_ETHERNET      = 0x06;      ///< Hardware address length
    constexpr UINT8  ARP_PLEN_IPV4          = 0x04;      ///< Protocol address length
    constexpr UINT16 ARP_OPER_REQUEST       = 0x0001;    ///< ARP request
    constexpr UINT16 ARP_OPER_REPLY         = 0x0002;    ///< ARP reply

    // =========================================================================
    //  ICMP (RFC 792)
    // =========================================================================

    constexpr UINT8  ICMP_TYPE_ECHO_REPLY   = 0x00;      ///< Echo reply
    constexpr UINT8  ICMP_TYPE_ECHO_REQUEST = 0x08;      ///< Echo request (ping)
    constexpr UINT8  ICMP_CODE_ZERO         = 0x00;      ///< Default code

    // =========================================================================
    //  TCP (RFC 793) — Flags
    // =========================================================================

    constexpr UINT8  TCP_FLAG_FIN           = 0x01;
    constexpr UINT8  TCP_FLAG_SYN           = 0x02;
    constexpr UINT8  TCP_FLAG_RST           = 0x04;
    constexpr UINT8  TCP_FLAG_PSH           = 0x08;
    constexpr UINT8  TCP_FLAG_ACK           = 0x10;
    constexpr UINT8  TCP_FLAG_URG           = 0x20;
    constexpr UINT8  TCP_FLAG_SYN_ACK      = TCP_FLAG_SYN | TCP_FLAG_ACK;
    constexpr UINT8  TCP_FLAG_FIN_ACK      = TCP_FLAG_FIN | TCP_FLAG_ACK;
    constexpr UINT8  TCP_FLAG_PSH_ACK      = TCP_FLAG_PSH | TCP_FLAG_ACK;

    constexpr UINT8  TCP_DATA_OFFSET_5     = 0x05;       ///< 20-byte TCP header (no options)
    constexpr UINT16 TCP_DEFAULT_WINDOW    = 0x2000;      ///< 8192-byte receive window

    // =========================================================================
    //  TCP State Machine
    // =========================================================================

    constexpr UINT32 TCP_STATE_CLOSED       = 0x00;
    constexpr UINT32 TCP_STATE_SYN_SENT     = 0x01;
    constexpr UINT32 TCP_STATE_ESTABLISHED  = 0x02;
    constexpr UINT32 TCP_STATE_FIN_WAIT     = 0x03;
    constexpr UINT32 TCP_STATE_CLOSED_DONE  = 0x04;

    // =========================================================================
    //  UDP (RFC 768)
    // =========================================================================

    constexpr UINT16 UDP_PORT_DNS           = 0x0035;     ///< DNS (port 53)
    constexpr UINT16 UDP_PORT_DHCP_CLIENT   = 0x0044;     ///< DHCP client (port 68)
    constexpr UINT16 UDP_PORT_DHCP_SERVER   = 0x0043;     ///< DHCP server (port 67)

    // =========================================================================
    //  DHCP (RFC 2131 / RFC 2132)
    // =========================================================================

    constexpr UINT8  DHCP_OP_REQUEST        = 0x01;       ///< Client → Server
    constexpr UINT8  DHCP_OP_REPLY          = 0x02;       ///< Server → Client
    constexpr UINT8  DHCP_HTYPE_ETHERNET    = 0x01;
    constexpr UINT8  DHCP_HLEN_ETHERNET     = 0x06;
    constexpr UINT32 DHCP_MAGIC_COOKIE      = 0x63825363; ///< RFC 2131 magic cookie

    /// DHCP Message Types (option 53)
    constexpr UINT8  DHCP_MSG_DISCOVER      = 0x01;
    constexpr UINT8  DHCP_MSG_OFFER         = 0x02;
    constexpr UINT8  DHCP_MSG_REQUEST       = 0x03;
    constexpr UINT8  DHCP_MSG_DECLINE       = 0x04;
    constexpr UINT8  DHCP_MSG_ACK           = 0x05;
    constexpr UINT8  DHCP_MSG_NAK           = 0x06;
    constexpr UINT8  DHCP_MSG_RELEASE       = 0x07;

    /// DHCP Option Codes
    constexpr UINT8  DHCP_OPT_PAD           = 0x00;       ///< Padding
    constexpr UINT8  DHCP_OPT_SUBNET_MASK   = 0x01;       ///< Subnet mask
    constexpr UINT8  DHCP_OPT_ROUTER        = 0x03;       ///< Default gateway
    constexpr UINT8  DHCP_OPT_DNS           = 0x06;       ///< DNS server(s)
    constexpr UINT8  DHCP_OPT_REQUESTED_IP  = 0x32;       ///< Requested IP address (50)
    constexpr UINT8  DHCP_OPT_LEASE_TIME    = 0x33;       ///< Lease time in seconds (51)
    constexpr UINT8  DHCP_OPT_MSG_TYPE      = 0x35;       ///< DHCP message type (53)
    constexpr UINT8  DHCP_OPT_SERVER_ID     = 0x36;       ///< Server identifier (54)
    constexpr UINT8  DHCP_OPT_PARAM_LIST    = 0x37;       ///< Parameter request list (55)
    constexpr UINT8  DHCP_OPT_END           = 0xFF;       ///< End of options

    /// DHCP State Machine
    constexpr UINT32 DHCP_STATE_DISCOVER    = 0x00;
    constexpr UINT32 DHCP_STATE_OFFER_RCVD  = 0x01;
    constexpr UINT32 DHCP_STATE_BOUND       = 0x02;

    // =========================================================================
    //  DNS (RFC 1035)
    // =========================================================================

    constexpr UINT16 DNS_FLAG_RESPONSE      = 0x8000;     ///< QR bit = response
    constexpr UINT16 DNS_FLAG_RECURSION     = 0x0100;     ///< Recursion desired
    constexpr UINT16 DNS_TYPE_A             = 0x0001;     ///< A record (IPv4)
    constexpr UINT16 DNS_CLASS_IN           = 0x0001;     ///< Internet class
    constexpr UINT8  DNS_PTR_MASK           = 0xC0;       ///< DNS name compression pointer
    constexpr UINT16 DNS_RDLEN_IPV4         = 0x0004;     ///< A record data length

    // =========================================================================
    //  SNP Receive Filter Flags
    // =========================================================================

    constexpr UINT32 SNP_FILTER_UNICAST     = 0x01;
    constexpr UINT32 SNP_FILTER_BROADCAST   = 0x04;
    constexpr UINT32 SNP_FILTER_ALL_MULTI   = 0x08;

    // =========================================================================
    //  Broadcast Addresses
    // =========================================================================

    constexpr UINT32 IPV4_BROADCAST         = 0xFFFFFFFF;
    static const UINT8 ETH_BROADCAST[6]     = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    // =========================================================================
    //  Google Public DNS (fallback)
    // =========================================================================

    /// 8.8.8.8 in network byte order
    constexpr UINT32 GOOGLE_DNS_NBO         = 0x08080808;

    // =========================================================================
    //  Timeouts & Limits (in microseconds unless noted)
    // =========================================================================

    constexpr UINT32 STALL_1MS              = 0x03E8;     ///< 1 ms
    constexpr UINT32 STALL_500US            = 0x01F4;     ///< 500 µs
    constexpr UINT32 STALL_100US            = 0x0064;     ///< 100 µs
    constexpr UINT32 STALL_10MS             = 0x2710;     ///< 10 ms

    constexpr UINT32 TIMEOUT_RETRANSMIT     = 0x1388;     ///< ~5 s of 1-ms ticks
    constexpr UINT32 TIMEOUT_DHCP_LOOPS     = 0x7A120;    ///< DHCP max polling iterations
    constexpr UINT32 TIMEOUT_ARP_LOOPS      = 0x30D40;    ///< ARP max polling iterations
    constexpr UINT32 TIMEOUT_TCP_LOOPS      = 0x7A120;    ///< TCP connect max iterations
    constexpr UINT32 TIMEOUT_TX_RETRIES     = 0x1388;     ///< Transmit completion retries
    constexpr UINT32 TIMEOUT_CLOSE_LOOPS    = 0x2710;     ///< TCP close drain iterations

    // =========================================================================
    //  Buffer Sizes
    // =========================================================================

    constexpr UINTN  PKT_BUF_SIZE           = 0x1000;     ///< 4096 bytes — rx/tx page
    constexpr UINTN  MAX_PKT_SIZE           = 0x05DC;     ///< 1500 bytes — max Ethernet payload
    constexpr UINTN  DHCP_PKT_SIZE          = 0x0258;     ///< DHCP packet buffer
    constexpr UINTN  DNS_PKT_SIZE           = 0x0258;     ///< DNS query buffer
    constexpr UINTN  ARP_PKT_SIZE           = 0x003C;     ///< ARP frame (60 bytes min)
    constexpr UINTN  HTTP_REQ_SIZE          = 0x0200;     ///< HTTP request buffer

    // =========================================================================
    //  Ephemeral Port Range (RFC 6335)
    // =========================================================================

    constexpr UINT16 EPHEMERAL_PORT_BASE    = 0xC000;     ///< 49152
    constexpr UINT16 EPHEMERAL_PORT_RANGE   = 0x4000;     ///< 16384 ports

    // =========================================================================
    //  DHCP Options Size Limit
    // =========================================================================

    constexpr UINTN  DHCP_OPT_MAX_SCAN      = 0xFA;      ///< Max bytes to scan in options

    // =========================================================================
    //  ARP Cache
    // =========================================================================

    constexpr UINTN  ARP_CACHE_SIZE         = 0x08;       ///< Max ARP cache entries
}
