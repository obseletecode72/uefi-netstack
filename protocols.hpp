#pragma once

/**
 * @file protocols.hpp
 * @brief Packet builders for DHCP, ARP, and DNS protocols.
 *
 * Each function constructs a complete Ethernet frame from scratch
 * (eth + ip + transport + payload) and transmits it via core::send_raw().
 */

// Forward declaration — core.hpp is included after this file
namespace core { static EFI_STATUS send_raw(VOID* data, UINTN len); }

namespace protocols
{
    /**
     * @brief Build and send a DHCP Discover or Request message.
     * @param type  DHCP message type (DHCP_MSG_DISCOVER or DHCP_MSG_REQUEST).
     * @param xid   Transaction ID for matching request/response.
     */
    static VOID send_dhcp(UINT8 type, UINT32 xid)
    {
        UINT8 pkt[constants::DHCP_PKT_SIZE];
        memory::local_zero_mem(pkt, sizeof(pkt));

        // --- Ethernet header ---
        types::eth_hdr* eth = (types::eth_hdr*)pkt;
        memory::local_mem_cpy(eth->dst, constants::ETH_BROADCAST, constants::ETH_ALEN);
        memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
        eth->type = utils::htons(constants::ETHERTYPE_IPV4);

        // --- IPv4 header ---
        types::ip_hdr* ip = (types::ip_hdr*)(pkt + sizeof(types::eth_hdr));
        ip->ihl_version = constants::IP_VERSION_IHL_DEFAULT;
        ip->tot_len = utils::htons(sizeof(types::ip_hdr) + sizeof(types::udp_hdr) + sizeof(types::dhcp_hdr));
        ip->id = utils::htons(0x01);
        ip->ttl = constants::IP_DEFAULT_TTL;
        ip->protocol = constants::IP_PROTO_UDP;
        ip->daddr = constants::IPV4_BROADCAST;
        ip->check = net_math::checksum(ip, sizeof(types::ip_hdr));

        // --- UDP header ---
        types::udp_hdr* udp = (types::udp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr));
        udp->source = utils::htons(constants::UDP_PORT_DHCP_CLIENT);
        udp->dest = utils::htons(constants::UDP_PORT_DHCP_SERVER);
        udp->len = utils::htons(sizeof(types::udp_hdr) + sizeof(types::dhcp_hdr));
        udp->check = 0x00;

        // --- DHCP payload ---
        types::dhcp_hdr* dhcp = (types::dhcp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::udp_hdr));
        dhcp->op = constants::DHCP_OP_REQUEST;
        dhcp->htype = constants::DHCP_HTYPE_ETHERNET;
        dhcp->hlen = constants::DHCP_HLEN_ETHERNET;
        dhcp->xid = utils::htonl(xid);
        dhcp->flags = utils::htons(0x8000);   // Broadcast flag
        memory::local_mem_cpy(dhcp->chaddr, globals::my_mac.Addr, constants::ETH_ALEN);
        dhcp->magic = utils::htonl(constants::DHCP_MAGIC_COOKIE);

        // --- DHCP options ---
        int opt = 0x00;

        // Option 53: Message Type
        dhcp->options[opt++] = constants::DHCP_OPT_MSG_TYPE;
        dhcp->options[opt++] = 0x01;
        dhcp->options[opt++] = type;

        if (type == constants::DHCP_MSG_DISCOVER)
        {
            // Option 55: Parameter Request List (subnet mask, router, DNS)
            dhcp->options[opt++] = constants::DHCP_OPT_PARAM_LIST;
            dhcp->options[opt++] = 0x03;
            dhcp->options[opt++] = constants::DHCP_OPT_SUBNET_MASK;
            dhcp->options[opt++] = constants::DHCP_OPT_ROUTER;
            dhcp->options[opt++] = constants::DHCP_OPT_DNS;
        }
        else if (type == constants::DHCP_MSG_REQUEST)
        {
            // Option 50: Requested IP Address
            dhcp->options[opt++] = constants::DHCP_OPT_REQUESTED_IP;
            dhcp->options[opt++] = 0x04;
            UINT32 tmp_ip = globals::my_ip;
            memory::local_mem_cpy(&dhcp->options[opt], &tmp_ip, 0x04);
            opt += 0x04;

            // Option 54: Server Identifier
            dhcp->options[opt++] = constants::DHCP_OPT_SERVER_ID;
            dhcp->options[opt++] = 0x04;
            UINT32 tmp_sip = globals::dhcp_server_ip;
            memory::local_mem_cpy(&dhcp->options[opt], &tmp_sip, 0x04);
            opt += 0x04;
        }

        // End marker
        dhcp->options[opt++] = constants::DHCP_OPT_END;

        core::send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::udp_hdr) + sizeof(types::dhcp_hdr));
    }

    /**
     * @brief Send an ARP Request for the given IPv4 address.
     * @param target_ip  IP address to resolve (network byte order).
     */
    static VOID arp_request(UINT32 target_ip)
    {
        UINT8 pkt[constants::ARP_PKT_SIZE];
        memory::local_zero_mem(pkt, sizeof(pkt));

        types::eth_hdr* eth = (types::eth_hdr*)pkt;
        memory::local_mem_cpy(eth->dst, constants::ETH_BROADCAST, constants::ETH_ALEN);
        memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
        eth->type = utils::htons(constants::ETHERTYPE_ARP);

        types::arp_hdr* arp = (types::arp_hdr*)(pkt + sizeof(types::eth_hdr));
        arp->htype = utils::htons(constants::ARP_HTYPE_ETHERNET);
        arp->ptype = utils::htons(constants::ARP_PTYPE_IPV4);
        arp->hlen = constants::ARP_HLEN_ETHERNET;
        arp->plen = constants::ARP_PLEN_IPV4;
        arp->oper = utils::htons(constants::ARP_OPER_REQUEST);
        memory::local_mem_cpy(arp->sha, globals::my_mac.Addr, constants::ETH_ALEN);
        arp->spa = globals::my_ip;
        arp->tpa = target_ip;

        core::send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::arp_hdr));
    }

    /**
     * @brief Build and send a DNS A-record query for the given hostname.
     * @param hostname  Null-terminated ASCII hostname (e.g. "example.com").
     */
    static VOID dns_query(const CHAR8* hostname)
    {
        UINT8 pkt[constants::DNS_PKT_SIZE];
        memory::local_zero_mem(pkt, sizeof(pkt));

        // --- Ethernet ---
        types::eth_hdr* eth = (types::eth_hdr*)pkt;
        memory::local_mem_cpy(eth->dst, globals::router_mac, constants::ETH_ALEN);
        memory::local_mem_cpy(eth->src, globals::my_mac.Addr, constants::ETH_ALEN);
        eth->type = utils::htons(constants::ETHERTYPE_IPV4);

        // --- IPv4 ---
        types::ip_hdr* ip = (types::ip_hdr*)(pkt + sizeof(types::eth_hdr));
        ip->ihl_version = constants::IP_VERSION_IHL_DEFAULT;
        ip->id = utils::htons(rng::get_u32() & 0xFFFF);
        ip->ttl = constants::IP_DEFAULT_TTL;
        ip->protocol = constants::IP_PROTO_UDP;
        ip->saddr = globals::my_ip;
        ip->daddr = (globals::dns_server_ip != 0x00) ? globals::dns_server_ip : utils::htonl(constants::GOOGLE_DNS_NBO);

        // --- UDP ---
        types::udp_hdr* udp = (types::udp_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr));
        globals::dns_local_port = rng::get_ephemeral_port();
        udp->source = utils::htons(globals::dns_local_port);
        udp->dest = utils::htons(constants::UDP_PORT_DNS);

        // --- DNS header ---
        types::dns_hdr* dns = (types::dns_hdr*)(pkt + sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::udp_hdr));
        globals::dns_current_id = rng::get_u32() & 0xFFFF;
        dns->id = utils::htons(globals::dns_current_id);
        dns->flags = utils::htons(constants::DNS_FLAG_RECURSION);
        dns->qdcount = utils::htons(0x01);

        // --- Encode hostname as DNS QNAME ---
        UINT8* qname = (UINT8*)dns + sizeof(types::dns_hdr);
        const CHAR8* p = hostname;
        UINT8* len_byte = qname++;
        UINT8 label_len = 0x00;

        while (*p != 0x00)
        {
            if (*p == '.')
            {
                *len_byte = label_len;
                len_byte = qname++;
                label_len = 0x00;
            }
            else
            {
                *qname++ = *p;
                label_len++;
            }
            p++;
        }
        *len_byte = label_len;
        *qname++ = 0x00;    // Root label

        // QTYPE = A (1), QCLASS = IN (1)
        *qname++ = 0x00; *qname++ = (UINT8)constants::DNS_TYPE_A;
        *qname++ = 0x00; *qname++ = (UINT8)constants::DNS_CLASS_IN;

        // --- Finalize lengths & checksums ---
        UINTN dns_len = (UINTN)(qname - (UINT8*)dns);
        udp->len = utils::htons((UINT16)(sizeof(types::udp_hdr) + dns_len));
        ip->tot_len = utils::htons((UINT16)(sizeof(types::ip_hdr) + sizeof(types::udp_hdr) + dns_len));
        ip->check = net_math::checksum(ip, sizeof(types::ip_hdr));
        udp->check = net_math::pseudo_checksum(ip->saddr, ip->daddr, constants::IP_PROTO_UDP, udp, utils::ntohs(udp->len));

        if (udp->check == 0x00)
        {
            udp->check = 0xFFFF;  // RFC 768: zero checksum is transmitted as all ones
        }

        core::send_raw(pkt, sizeof(types::eth_hdr) + sizeof(types::ip_hdr) + sizeof(types::udp_hdr) + dns_len);
    }
}