#pragma once

/**
 * @file icmp.hpp
 * @brief ICMP Echo Request/Reply (Ping) implementation.
 *
 * Provides both sending echo requests and responding to incoming
 * echo requests (making the device visible on the network).
 */

namespace icmp
{
    /**
     * @brief Send an ICMP Echo Request to the specified IP.
     * @param target_ip  Destination IP address (network byte order).
     * @param id         Echo identifier.
     * @param seq        Echo sequence number.
     */
    static VOID send_echo_request(UINT32 target_ip, UINT16 id, UINT16 seq);

    /**
     * @brief Handle an incoming ICMP packet (called from core::poll).
     * @param ip    Pointer to the IP header.
     * @param icmp  Pointer to the ICMP header.
     * @param len   Total ICMP payload length including header.
     */
    static VOID handle_icmp(types::ip_hdr* ip, types::icmp_hdr* icmp, UINTN len);
}
