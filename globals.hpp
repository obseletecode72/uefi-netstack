#pragma once

/**
 * @file globals.hpp
 * @brief Global state for the network stack.
 *
 * Houses all mutable state including EFI service pointers, MAC/IP
 * configuration, per-protocol session variables, and receive buffers.
 *
 * @note Because EFI applications run single-threaded with no OS scheduler,
 *       plain static globals are safe here — no mutex is required.
 */

namespace globals
{
    // =========================================================================
    //  EFI Service Pointers
    // =========================================================================

    static EFI_BOOT_SERVICES*             bs           = nullptr;  ///< Boot Services table
    static EFI_RUNTIME_SERVICES*          rt           = nullptr;  ///< Runtime Services table
    static EFI_SYSTEM_TABLE*              st           = nullptr;  ///< System Table
    static EFI_SIMPLE_NETWORK_PROTOCOL*   snp          = nullptr;  ///< SNP interface handle
    static EFI_HANDLE                     image_handle = nullptr;  ///< Loaded image handle

    // =========================================================================
    //  Network Identity (configured by DHCP or static)
    // =========================================================================

    static EFI_MAC_ADDRESS my_mac;                                  ///< Local MAC address
    static UINT32          my_ip           = 0x00;                  ///< Local IPv4 address
    static UINT32          subnet_mask     = 0x00;                  ///< Subnet mask
    static UINT32          router_ip       = 0x00;                  ///< Default gateway IP
    static UINT32          dhcp_server_ip  = 0x00;                  ///< DHCP server IP
    static UINT32          dns_server_ip   = 0x00;                  ///< DNS server IP
    static UINT32          dhcp_lease_time = 0x00;                  ///< DHCP lease time (seconds)
    static UINT8           router_mac[0x06] = { 0x00 };             ///< Gateway MAC address

    // =========================================================================
    //  Packet Buffers (allocated as EFI pages below 4 GB)
    // =========================================================================

    static UINT8* rx_pkt = nullptr;     ///< Receive packet buffer (1 page)
    static UINT8* tx_pkt = nullptr;     ///< Transmit packet buffer (1 page)

    // =========================================================================
    //  PRNG State
    // =========================================================================

    static UINT32 rng_seed = 0x075BCD15; ///< Seeded from EFI RTC at init

    // =========================================================================
    //  ARP Resolution State
    // =========================================================================

    static UINT32  arp_target_ip          = 0x00;
    static UINT8   arp_target_mac[0x06]   = { 0x00 };
    static BOOLEAN arp_resolved           = FALSE;

    // =========================================================================
    //  DNS Resolution State
    // =========================================================================

    static UINT16  dns_current_id         = 0x00;   ///< Current DNS transaction ID
    static UINT16  dns_local_port         = 0x00;   ///< DNS query source port (separate from TCP)
    static UINT32  dns_resolved_ip        = 0x00;   ///< Result of last DNS A-record lookup
    static BOOLEAN dns_resolved           = FALSE;   ///< TRUE when a response has been received

    // =========================================================================
    //  TCP Session State
    // =========================================================================

    static UINT16  tcp_local_port         = 0x00;
    static UINT16  tcp_remote_port        = 0x00;
    static UINT32  tcp_remote_ip          = 0x00;
    static UINT32  tcp_seq                = 0x00;   ///< Next sequence number to send
    static UINT32  tcp_ack                = 0x00;   ///< Next ACK number to send
    static UINT32  tcp_state              = 0x00;   ///< Current state (constants::TCP_STATE_*)
    static UINT8*  tcp_rx_buffer          = nullptr; ///< User-supplied receive buffer
    static UINTN   tcp_rx_max_len         = 0x00;
    static UINTN   tcp_rx_current_len     = 0x00;
    static BOOLEAN tcp_rx_done            = FALSE;

    // =========================================================================
    //  UDP Receive State
    // =========================================================================

    static UINT16  udp_local_port         = 0x00;
    static UINT8*  udp_rx_buffer          = nullptr;
    static UINTN   udp_rx_max_len         = 0x00;
    static UINTN   udp_rx_current_len     = 0x00;
    static BOOLEAN udp_rx_done            = FALSE;

    // =========================================================================
    //  ICMP Ping State
    // =========================================================================

    static UINT16  ping_id                = 0x00;   ///< ICMP echo identifier
    static UINT16  ping_seq               = 0x00;   ///< ICMP echo sequence number
    static BOOLEAN ping_reply_received    = FALSE;   ///< TRUE when echo reply arrives
}
