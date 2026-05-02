#pragma once

/**
 * @file core.hpp
 * @brief Network core: raw transmit, packet dispatcher, and TCP state machine.
 *
 * This module handles:
 *  - Raw frame transmission via SNP with completion polling
 *  - Incoming packet dispatch (ARP, IPv4 -> ICMP / UDP / TCP)
 *  - ARP reply handling + cache updates
 *  - DNS response parsing
 *  - Full TCP state machine (SYN_SENT -> ESTABLISHED -> FIN_WAIT)
 *  - ICMP echo request/reply
 */

namespace core
{
    // -----------------------------------------------------------------
    //  Raw Transmit
    // -----------------------------------------------------------------

    /**
     * @brief Transmit a raw Ethernet frame via SNP.
     *
     * Copies the frame into the DMA-safe tx buffer, calls Transmit(),
     * then polls GetStatus() until the NIC signals completion.
     *
     * @param data  Pointer to the complete Ethernet frame.
     * @param len   Frame length in bytes.
     * @return      EFI_SUCCESS or the SNP error code.
     */
    static EFI_STATUS send_raw(VOID* data, UINTN len)
    {
        memory::local_mem_cpy(globals::tx_pkt, data, len);
        UINT32 int_status = 0x00;
        VOID* tx_buf = nullptr;

        globals::snp->GetStatus(globals::snp, &int_status, &tx_buf);
        EFI_STATUS st = globals::snp->Transmit(globals::snp, 0x00, len, globals::tx_pkt, nullptr, nullptr, nullptr);

        if (EFI_ERROR(st))
        {
            return st;
        }

        // Poll for transmit completion
        UINT32 retries = constants::TIMEOUT_TX_RETRIES;
        while (retries > 0x00)
        {
            tx_buf = nullptr;
            st = globals::snp->GetStatus(globals::snp, &int_status, &tx_buf);
            if (!EFI_ERROR(st) && tx_buf != nullptr)
            {
                break;
            }
            globals::bs->Stall(constants::STALL_500US);
            retries--;
        }
        return EFI_SUCCESS;
    }

    // -----------------------------------------------------------------
    //  ARP Handler
    // -----------------------------------------------------------------

    /// Process an incoming ARP frame (request or reply).
    static VOID handle_arp(types::arp_hdr* arp)
    {
        UINT16 oper = utils::ntohs(arp->oper);

        if (oper == constants::ARP_OPER_REPLY)
        {
            // Cache the sender's MAC
            arp_cache::update(arp->spa, arp->sha);

            // Complete any pending ARP resolution
            if (arp->spa == globals::arp_target_ip)
            {
                memory::local_mem_cpy(globals::arp_target_mac, arp->sha, constants::ETH_ALEN);
                globals::arp_resolved = TRUE;
            }
            if (arp->spa == globals::router_ip)
            {
                memory::local_mem_cpy(globals::router_mac, arp->sha, constants::ETH_ALEN);
            }
        }
        else if (oper == constants::ARP_OPER_REQUEST)
        {
            // Reply to ARP requests for our IP
            if (arp->tpa == globals::my_ip && globals::my_ip != 0x00)
            {
                UINT8 pkt[constants::ARP_PKT_SIZE];
                memory::local_zero_mem(pkt, sizeof(pkt));

                types::eth_hdr* eth = (types::eth_hdr*)pkt;
                memory::local_mem_cpy(eth->dst, arp->sha, constants::ETH_ALEN);
                memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
                eth->type = utils::htons(constants::ETHERTYPE_ARP);

                types::arp_hdr* reply = (types::arp_hdr*)(pkt + sizeof(types::eth_hdr));
                reply->htype = utils::htons(constants::ARP_HTYPE_ETHERNET);
                reply->ptype = utils::htons(constants::ARP_PTYPE_IPV4);
                reply->hlen = constants::ARP_HLEN_ETHERNET;
                reply->plen = constants::ARP_PLEN_IPV4;
                reply->oper = utils::htons(constants::ARP_OPER_REPLY);
                memory::local_mem_cpy(reply->sha, globals::my_mac.Addr, constants::ETH_ALEN);
                reply->spa = globals::my_ip;
                memory::local_mem_cpy(reply->tha, arp->sha, constants::ETH_ALEN);
                reply->tpa = arp->spa;

                send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::arp_hdr));
            }
        }
    }

    // -----------------------------------------------------------------
    //  ICMP Handler
    // -----------------------------------------------------------------

    /// Send an ICMP Echo Request packet.
    static VOID send_icmp_echo(UINT32 target_ip, UINT16 id, UINT16 seq)
    {
        UINT8 pkt[sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::icmp_hdr) + 0x20];
        memory::local_zero_mem(pkt, sizeof(pkt));

        types::eth_hdr* eth = (types::eth_hdr*)pkt;
        memory::local_mem_cpy(eth->dst, globals::router_mac, constants::ETH_ALEN);
        memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
        eth->type = utils::htons(constants::ETHERTYPE_IPV4);

        UINTN icmp_payload = 0x20;  // 32 bytes of padding
        types::ip_hdr* ip = (types::ip_hdr*)(pkt + sizeof(types::eth_hdr));
        ip->ihl_version = constants::IP_VERSION_IHL_DEFAULT;
        ip->tot_len = utils::htons((UINT16)(sizeof(types::ip_hdr) + sizeof(types::icmp_hdr) + icmp_payload));
        ip->id = utils::htons(rng::get_u32() & 0xFFFF);
        ip->ttl = constants::IP_DEFAULT_TTL;
        ip->protocol = constants::IP_PROTO_ICMP;
        ip->saddr = globals::my_ip;
        ip->daddr = target_ip;
        ip->check = net_math::checksum(ip, sizeof(types::ip_hdr));

        types::icmp_hdr* icmp = (types::icmp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr));
        icmp->type = constants::ICMP_TYPE_ECHO_REQUEST;
        icmp->code = constants::ICMP_CODE_ZERO;
        icmp->id = utils::htons(id);
        icmp->seq = utils::htons(seq);

        // Fill payload with pattern
        UINT8* payload = (UINT8*)icmp + sizeof(types::icmp_hdr);
        for (UINTN i = 0x00; i < icmp_payload; i++)
        {
            payload[i] = (UINT8)(i & 0xFF);
        }

        icmp->checksum = net_math::checksum(icmp, sizeof(types::icmp_hdr) + icmp_payload);

        send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::icmp_hdr) + icmp_payload);
    }

    /// Handle incoming ICMP packets (echo request -> reply, echo reply -> signal).
    static VOID handle_icmp(types::ip_hdr* ip, types::icmp_hdr* icmp, UINTN len)
    {
        if (icmp->type == constants::ICMP_TYPE_ECHO_REQUEST && icmp->code == constants::ICMP_CODE_ZERO)
        {
            // Reply to ping — swap addresses and change type
            UINTN total = sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + len;
            if (total > constants::MAX_PKT_SIZE) return;

            UINT8 pkt[constants::MAX_PKT_SIZE];
            memory::local_zero_mem(pkt, total);

            types::eth_hdr* eth = (types::eth_hdr*)pkt;
            memory::local_mem_cpy(eth->dst, globals::router_mac, constants::ETH_ALEN);
            memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
            eth->type = utils::htons(constants::ETHERTYPE_IPV4);

            types::ip_hdr* rip = (types::ip_hdr*)(pkt + sizeof(types::eth_hdr));
            rip->ihl_version = constants::IP_VERSION_IHL_DEFAULT;
            rip->tot_len = utils::htons((UINT16)(sizeof(types::ip_hdr) + len));
            rip->id = utils::htons(rng::get_u32() & 0xFFFF);
            rip->ttl = constants::IP_DEFAULT_TTL;
            rip->protocol = constants::IP_PROTO_ICMP;
            rip->saddr = globals::my_ip;
            rip->daddr = ip->saddr;
            rip->check = net_math::checksum(rip, sizeof(types::ip_hdr));

            types::icmp_hdr* ricmp = (types::icmp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr));
            memory::local_mem_cpy(ricmp, icmp, len);
            ricmp->type = constants::ICMP_TYPE_ECHO_REPLY;
            ricmp->checksum = 0x00;
            ricmp->checksum = net_math::checksum(ricmp, len);

            send_raw(pkt, total);
        }
        else if (icmp->type == constants::ICMP_TYPE_ECHO_REPLY)
        {
            // Signal that a ping reply was received
            if (utils::ntohs(icmp->id) == globals::ping_id &&
                utils::ntohs(icmp->seq) == globals::ping_seq)
            {
                globals::ping_reply_received = TRUE;
            }
        }
    }

    // -----------------------------------------------------------------
    //  UDP Handler (DNS responses + user datagrams)
    // -----------------------------------------------------------------

    /// Process an incoming UDP datagram.
    static VOID handle_udp(types::ip_hdr* ip, types::udp_hdr* udp, UINTN data_len)
    {
        UINT16 dst_port = utils::ntohs(udp->dest);
        UINT16 src_port = utils::ntohs(udp->source);

        // --- User UDP receive ---
        if (dst_port == globals::udp_local_port && globals::udp_local_port != 0x00)
        {
            UINTN payload_len = utils::ntohs(udp->len) - sizeof(types::udp_hdr);
            if (payload_len > 0x00 && globals::udp_rx_buffer != nullptr)
            {
                UINTN copy_len = (payload_len > globals::udp_rx_max_len) ? globals::udp_rx_max_len : payload_len;
                memory::local_mem_cpy(globals::udp_rx_buffer, (UINT8*)udp + sizeof(types::udp_hdr), copy_len);
                globals::udp_rx_current_len = copy_len;
                globals::udp_rx_done = TRUE;
            }
        }

        // --- DNS response ---
        if (dst_port == globals::dns_local_port && globals::dns_local_port != 0x00 && src_port == constants::UDP_PORT_DNS)
        {
            types::dns_hdr* dns = (types::dns_hdr*)((UINT8*)udp + sizeof(types::udp_hdr));
            if (dns->id != utils::htons(globals::dns_current_id)) return;

            UINT16 flags = utils::ntohs(dns->flags);
            if ((flags & constants::DNS_FLAG_RESPONSE) == 0x00) return;
            if (utils::ntohs(dns->ancount) == 0x00) return;

            // Skip question section
            UINT8* p = (UINT8*)dns + sizeof(types::dns_hdr);
            UINT16 qdcount = utils::ntohs(dns->qdcount);
            for (UINT16 i = 0x00; i < qdcount; i++)
            {
                while (*p != 0x00) { p += *p + 0x01; }
                p += 0x05;  // null + QTYPE(2) + QCLASS(2)
            }

            // Parse answer section — find first A record
            UINT16 ancount = utils::ntohs(dns->ancount);
            for (UINT16 i = 0x00; i < ancount; i++)
            {
                // Skip name (may be compressed)
                if ((*p & constants::DNS_PTR_MASK) == constants::DNS_PTR_MASK)
                    p += 0x02;
                else
                {
                    while (*p != 0x00) { p += *p + 0x01; }
                    p++;
                }

                UINT16 rtype = (p[0x00] << 0x08) | p[0x01];
                p += 0x08;  // TYPE(2) + CLASS(2) + TTL(4)
                UINT16 rdlen = (p[0x00] << 0x08) | p[0x01];
                p += 0x02;

                if (rtype == constants::DNS_TYPE_A && rdlen == constants::DNS_RDLEN_IPV4)
                {
                    memory::local_mem_cpy(&globals::dns_resolved_ip, p, 0x04);
                    globals::dns_resolved = TRUE;
                    break;
                }
                p += rdlen;
            }
        }
    }

    // -----------------------------------------------------------------
    //  TCP — Internal Send
    // -----------------------------------------------------------------

    /**
     * @brief Build and send a TCP segment.
     * @param flags     TCP flag bitmask (SYN, ACK, FIN, PSH, etc.).
     * @param seq       Sequence number (host byte order).
     * @param ack       Acknowledgment number (host byte order).
     * @param data      Payload data (may be nullptr).
     * @param data_len  Payload length in bytes.
     */
    static VOID send_tcp_internal(UINT8 flags, UINT32 seq, UINT32 ack, const UINT8* data, UINTN data_len)
    {
        UINT8 pkt[constants::MAX_PKT_SIZE];
        memory::local_zero_mem(pkt, sizeof(pkt));

        types::eth_hdr* eth = (types::eth_hdr*)pkt;
        memory::local_mem_cpy(eth->dst, globals::router_mac, constants::ETH_ALEN);
        memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
        eth->type = utils::htons(constants::ETHERTYPE_IPV4);

        types::ip_hdr* ip = (types::ip_hdr*)(pkt + sizeof(types::eth_hdr));
        ip->ihl_version = constants::IP_VERSION_IHL_DEFAULT;
        ip->tot_len = utils::htons((UINT16)(sizeof(types::ip_hdr) + sizeof(types::tcp_hdr) + data_len));
        ip->id = utils::htons(rng::get_u32() & 0xFFFF);
        ip->ttl = constants::IP_DEFAULT_TTL;
        ip->protocol = constants::IP_PROTO_TCP;
        ip->saddr = globals::my_ip;
        ip->daddr = globals::tcp_remote_ip;
        ip->check = net_math::checksum(ip, sizeof(types::ip_hdr));

        types::tcp_hdr* tcp = (types::tcp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr));
        tcp->source = utils::htons(globals::tcp_local_port);
        tcp->dest = utils::htons(globals::tcp_remote_port);
        tcp->seq = utils::htonl(seq);
        tcp->ack_seq = utils::htonl(ack);
        tcp->res1_doff_flags = utils::htons((constants::TCP_DATA_OFFSET_5 << 0x0C) | flags);
        tcp->window = utils::htons(constants::TCP_DEFAULT_WINDOW);

        if (data_len > 0x00 && data != nullptr)
        {
            memory::local_mem_cpy((UINT8*)tcp + sizeof(types::tcp_hdr), data, data_len);
        }

        tcp->check = net_math::pseudo_checksum(ip->saddr, ip->daddr, constants::IP_PROTO_TCP, tcp, (UINT16)(sizeof(types::tcp_hdr) + data_len));

        send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::tcp_hdr) + data_len);
    }

    // -----------------------------------------------------------------
    //  TCP Handler — State Machine
    // -----------------------------------------------------------------

    /// Process an incoming TCP segment through the state machine.
    static VOID handle_tcp(types::ip_hdr* ip, types::tcp_hdr* tcp, UINTN data_len)
    {
        if (utils::ntohs(tcp->dest) != globals::tcp_local_port || globals::tcp_local_port == 0x00)
            return;

        UINT16 flags = utils::ntohs(tcp->res1_doff_flags) & 0x3F;
        UINT32 rx_seq = utils::ntohl(tcp->seq);
        UINT32 rx_ack = utils::ntohl(tcp->ack_seq);
        UINTN tcp_hlen = ((utils::ntohs(tcp->res1_doff_flags) >> 0x0C) & 0x0F) * 0x04;
        UINTN payload_len = utils::ntohs(ip->tot_len) - ((ip->ihl_version & 0x0F) * 0x04) - tcp_hlen;

        // RST handling — abort connection
        if (flags & constants::TCP_FLAG_RST)
        {
            globals::tcp_state = constants::TCP_STATE_CLOSED;
            globals::tcp_rx_done = TRUE;
            return;
        }

        if (globals::tcp_state == constants::TCP_STATE_SYN_SENT)
        {
            // Expecting SYN+ACK
            if ((flags & constants::TCP_FLAG_SYN_ACK) == constants::TCP_FLAG_SYN_ACK)
            {
                globals::tcp_seq = rx_ack;
                globals::tcp_ack = rx_seq + 0x01;
                send_tcp_internal(constants::TCP_FLAG_ACK, globals::tcp_seq, globals::tcp_ack, nullptr, 0x00);
                globals::tcp_state = constants::TCP_STATE_ESTABLISHED;
            }
        }
        else if (globals::tcp_state == constants::TCP_STATE_ESTABLISHED ||
                 globals::tcp_state == constants::TCP_STATE_FIN_WAIT)
        {
            // Receive data
            if (payload_len > 0x00 && globals::tcp_rx_buffer != nullptr)
            {
                UINTN space_left = globals::tcp_rx_max_len - globals::tcp_rx_current_len;
                UINTN copy_len = (payload_len > space_left) ? space_left : payload_len;

                if (copy_len > 0x00)
                {
                    UINT8* payload = (UINT8*)tcp + tcp_hlen;
                    memory::local_mem_cpy(globals::tcp_rx_buffer + globals::tcp_rx_current_len, payload, copy_len);
                    globals::tcp_rx_current_len += copy_len;
                    globals::tcp_rx_done = TRUE;
                }
            }

            if (payload_len > 0x00)
            {
                globals::tcp_seq = rx_ack;
                globals::tcp_ack = rx_seq + payload_len;
                send_tcp_internal(constants::TCP_FLAG_ACK, globals::tcp_seq, globals::tcp_ack, nullptr, 0x00);
            }

            // FIN received — close
            if (flags & constants::TCP_FLAG_FIN)
            {
                globals::tcp_seq = rx_ack;
                globals::tcp_ack = rx_seq + payload_len + 0x01;
                send_tcp_internal(constants::TCP_FLAG_FIN_ACK, globals::tcp_seq, globals::tcp_ack, nullptr, 0x00);
                globals::tcp_state = constants::TCP_STATE_CLOSED_DONE;
            }
        }
    }

    // -----------------------------------------------------------------
    //  UDP Send Helper
    // -----------------------------------------------------------------

    /// Build and send a UDP datagram to the specified IP:port.
    static VOID send_udp(UINT32 dest_ip, UINT16 dest_port, UINT16 src_port, const UINT8* data, UINTN data_len)
    {
        UINT8 pkt[constants::MAX_PKT_SIZE];
        memory::local_zero_mem(pkt, sizeof(pkt));

        types::eth_hdr* eth = (types::eth_hdr*)pkt;
        memory::local_mem_cpy(eth->dst, globals::router_mac, constants::ETH_ALEN);
        memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
        eth->type = utils::htons(constants::ETHERTYPE_IPV4);

        types::ip_hdr* ip = (types::ip_hdr*)(pkt + sizeof(types::eth_hdr));
        ip->ihl_version = constants::IP_VERSION_IHL_DEFAULT;
        ip->tot_len = utils::htons((UINT16)(sizeof(types::ip_hdr) + sizeof(types::udp_hdr) + data_len));
        ip->id = utils::htons(rng::get_u32() & 0xFFFF);
        ip->ttl = constants::IP_DEFAULT_TTL;
        ip->protocol = constants::IP_PROTO_UDP;
        ip->saddr = globals::my_ip;
        ip->daddr = dest_ip;
        ip->check = net_math::checksum(ip, sizeof(types::ip_hdr));

        types::udp_hdr* udp = (types::udp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr));
        udp->source = utils::htons(src_port);
        udp->dest = utils::htons(dest_port);
        udp->len = utils::htons((UINT16)(sizeof(types::udp_hdr) + data_len));

        if (data_len > 0x00 && data != nullptr)
        {
            memory::local_mem_cpy((UINT8*)udp + sizeof(types::udp_hdr), data, data_len);
        }

        udp->check = net_math::pseudo_checksum(ip->saddr, ip->daddr, constants::IP_PROTO_UDP, udp, utils::ntohs(udp->len));
        if (udp->check == 0x00) udp->check = 0xFFFF;

        send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::udp_hdr) + data_len);
    }

    // -----------------------------------------------------------------
    //  Main Packet Dispatcher
    // -----------------------------------------------------------------

    /**
     * @brief Poll the NIC for one incoming frame and dispatch it.
     *
     * Reads a single frame via SNP->Receive and routes it to the
     * appropriate handler based on EtherType and IP protocol number.
     * On non-transient receive errors, resets the SNP interface.
     */
    static VOID poll()
    {
        UINTN buf_size = constants::PKT_BUF_SIZE;
        EFI_STATUS st = globals::snp->Receive(globals::snp, nullptr, &buf_size, globals::rx_pkt, nullptr, nullptr, nullptr);

        if (!EFI_ERROR(st))
        {
            types::eth_hdr* eth = (types::eth_hdr*)globals::rx_pkt;

            if (eth->type == utils::htons(constants::ETHERTYPE_ARP))
            {
                types::arp_hdr* arp = (types::arp_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr));
                handle_arp(arp);
            }
            else if (eth->type == utils::htons(constants::ETHERTYPE_IPV4))
            {
                types::ip_hdr* ip = (types::ip_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr));
                UINTN ip_hlen = (ip->ihl_version & 0x0F) * 0x04;
                if (ip_hlen < constants::IP_HDR_MIN_LEN) ip_hlen = constants::IP_HDR_MIN_LEN;

                if (ip->protocol == constants::IP_PROTO_ICMP)
                {
                    types::icmp_hdr* icmp = (types::icmp_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr) + ip_hlen);
                    UINTN icmp_len = utils::ntohs(ip->tot_len) - ip_hlen;
                    handle_icmp(ip, icmp, icmp_len);
                }
                else if (ip->protocol == constants::IP_PROTO_UDP)
                {
                    types::udp_hdr* udp = (types::udp_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr) + ip_hlen);
                    handle_udp(ip, udp, utils::ntohs(ip->tot_len) - ip_hlen);
                }
                else if (ip->protocol == constants::IP_PROTO_TCP)
                {
                    types::tcp_hdr* tcp = (types::tcp_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr) + ip_hlen);
                    handle_tcp(ip, tcp, utils::ntohs(ip->tot_len) - ip_hlen);
                }
            }
        }
        else if (st != EFI_NOT_READY)
        {
            // Non-transient error — reset the NIC
            globals::snp->Reset(globals::snp, TRUE);
            globals::snp->ReceiveFilters(globals::snp,
                constants::SNP_FILTER_UNICAST | constants::SNP_FILTER_BROADCAST | constants::SNP_FILTER_ALL_MULTI,
                0x00, FALSE, 0x00, nullptr);
            globals::bs->Stall(constants::STALL_10MS);
        }
    }
}