#pragma once

/**
 * @file api.hpp
 * @brief Public API for the UEFI bare-metal network stack.
 *
 * This is the primary interface for user code. It provides:
 *  - init_network()        — DHCP-based network initialization
 *  - init_network_static() — Static IP configuration (no DHCP)
 *  - resolve_hostname()    — DNS A-record lookup
 *  - tcp_connect/send/receive/close() — TCP client operations
 *  - udp_send/udp_receive() — UDP datagram operations
 *  - ping()                — ICMP echo request/reply
 *  - http_get()            — Simple HTTP/1.1 GET request
 *
 * All functions return EFI_STATUS and block until completion or timeout.
 */

namespace api
{
    // =================================================================
    //  Network Initialization — DHCP
    // =================================================================

    /**
     * @brief Initialize the network stack via DHCP.
     *
     * Performs the following sequence:
     *  1. Seed the PRNG from the EFI Real-Time Clock
     *  2. Allocate DMA-safe packet buffers (below 4 GB)
     *  3. Locate and open the SNP protocol
     *  4. Start/initialize the NIC and configure receive filters
     *  5. Run the full DHCP handshake (DISCOVER → OFFER → REQUEST → ACK)
     *  6. Resolve the default gateway's MAC address via ARP
     *
     * @return EFI_SUCCESS on success, or an appropriate error code.
     */
    static EFI_STATUS init_network()
    {
        rng::init();

        // --- Allocate DMA-safe packet buffers ---
        EFI_PHYSICAL_ADDRESS phys_rx = 0xFFFFFFFF;
        EFI_PHYSICAL_ADDRESS phys_tx = 0xFFFFFFFF;

        if (EFI_ERROR(globals::bs->AllocatePages(AllocateMaxAddress, EfiBootServicesData, 0x01, &phys_rx)))
            return EFI_OUT_OF_RESOURCES;

        if (EFI_ERROR(globals::bs->AllocatePages(AllocateMaxAddress, EfiBootServicesData, 0x01, &phys_tx)))
            return EFI_OUT_OF_RESOURCES;

        globals::rx_pkt = (UINT8*)(UINTN)phys_rx;
        globals::tx_pkt = (UINT8*)(UINTN)phys_tx;

        // --- Locate SNP protocol ---
        EFI_GUID snp_guid = EFI_SIMPLE_NETWORK_PROTOCOL_GUID;
        UINTN handle_count = 0x00;
        EFI_HANDLE* handles = nullptr;
        EFI_STATUS status = globals::bs->LocateHandleBuffer(ByProtocol, &snp_guid, nullptr, &handle_count, &handles);

        if (EFI_ERROR(status) || handle_count == 0x00)
            return EFI_ERROR(status) ? status : EFI_NOT_FOUND;

        // --- Open SNP (disconnect existing driver if needed) ---
        status = globals::bs->OpenProtocol(handles[0x00], &snp_guid, (VOID**)&globals::snp,
                                           globals::image_handle, nullptr, EFI_OPEN_PROTOCOL_EXCLUSIVE);
        if (EFI_ERROR(status))
        {
            globals::bs->DisconnectController(handles[0x00], nullptr, nullptr);
            status = globals::bs->OpenProtocol(handles[0x00], &snp_guid, (VOID**)&globals::snp,
                                               globals::image_handle, nullptr, EFI_OPEN_PROTOCOL_EXCLUSIVE);
            if (EFI_ERROR(status))
                return status;
        }

        // --- Start and initialize the NIC ---
        if (globals::snp->Mode->State == EfiSimpleNetworkStarted)
            globals::snp->Stop(globals::snp);

        globals::bs->Stall(constants::STALL_10MS);
        globals::snp->Start(globals::snp);
        globals::bs->Stall(constants::STALL_10MS);
        globals::snp->Initialize(globals::snp, 0x00, 0x00);

        globals::snp->ReceiveFilters(globals::snp,
            constants::SNP_FILTER_UNICAST | constants::SNP_FILTER_BROADCAST | constants::SNP_FILTER_ALL_MULTI,
            0x00, FALSE, 0x00, nullptr);
        memory::local_mem_cpy(globals::my_mac.Addr, globals::snp->Mode->CurrentAddress.Addr, constants::ETH_ALEN);

        // --- DHCP handshake ---
        UINT32 dhcp_xid = rng::get_u32();  // Random transaction ID
        UINT32 timeout = 0x00;
        UINT32 dhcp_state = constants::DHCP_STATE_DISCOVER;
        UINT32 loops = 0x00;

        while (dhcp_state < constants::DHCP_STATE_BOUND)
        {
            if (loops >= constants::TIMEOUT_DHCP_LOOPS)
                break;

            if (timeout == 0x00)
            {
                if (dhcp_state == constants::DHCP_STATE_DISCOVER)
                    protocols::send_dhcp(constants::DHCP_MSG_DISCOVER, dhcp_xid);
                else if (dhcp_state == constants::DHCP_STATE_OFFER_RCVD)
                    protocols::send_dhcp(constants::DHCP_MSG_REQUEST, dhcp_xid);
                timeout = constants::TIMEOUT_RETRANSMIT;
            }

            UINTN buf_size = constants::PKT_BUF_SIZE;
            EFI_STATUS st = globals::snp->Receive(globals::snp, nullptr, &buf_size, globals::rx_pkt, nullptr, nullptr, nullptr);

            if (!EFI_ERROR(st))
            {
                types::eth_hdr* eth = (types::eth_hdr*)globals::rx_pkt;
                if (eth->type == utils::htons(constants::ETHERTYPE_IPV4))
                {
                    types::ip_hdr* ip = (types::ip_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr));
                    UINTN ip_hlen = (ip->ihl_version & 0x0F) * 0x04;
                    if (ip_hlen < constants::IP_HDR_MIN_LEN) ip_hlen = constants::IP_HDR_MIN_LEN;

                    if (ip->protocol == constants::IP_PROTO_UDP)
                    {
                        types::udp_hdr* udp = (types::udp_hdr*)(globals::rx_pkt + sizeof(types::eth_hdr) + ip_hlen);
                        if (udp->dest == utils::htons(constants::UDP_PORT_DHCP_CLIENT))
                        {
                            types::dhcp_hdr* dhcp = (types::dhcp_hdr*)((UINT8*)udp + sizeof(types::udp_hdr));
                            if (dhcp->magic == utils::htonl(constants::DHCP_MAGIC_COOKIE))
                            {
                                // Parse DHCP options
                                UINT8 msg_type = 0x00;
                                UINT8* p = dhcp->options;
                                while (*p != constants::DHCP_OPT_END)
                                {
                                    if (p >= dhcp->options + constants::DHCP_OPT_MAX_SCAN)
                                        break;

                                    if (*p == constants::DHCP_OPT_MSG_TYPE && p[0x01] >= 0x01)
                                        msg_type = p[0x02];

                                    if (*p == constants::DHCP_OPT_ROUTER && p[0x01] >= 0x04)
                                        memory::local_mem_cpy(&globals::router_ip, p + 0x02, 0x04);

                                    if (*p == constants::DHCP_OPT_DNS && p[0x01] >= 0x04)
                                        memory::local_mem_cpy(&globals::dns_server_ip, p + 0x02, 0x04);

                                    if (*p == constants::DHCP_OPT_SUBNET_MASK && p[0x01] >= 0x04)
                                        memory::local_mem_cpy(&globals::subnet_mask, p + 0x02, 0x04);

                                    if (*p == constants::DHCP_OPT_LEASE_TIME && p[0x01] >= 0x04)
                                    {
                                        UINT32 lt = 0x00;
                                        memory::local_mem_cpy(&lt, p + 0x02, 0x04);
                                        globals::dhcp_lease_time = utils::ntohl(lt);
                                    }

                                    if (*p == constants::DHCP_OPT_PAD) { p++; continue; }
                                    p += p[0x01] + 0x02;
                                }

                                // State transitions
                                if (dhcp_state == constants::DHCP_STATE_DISCOVER && dhcp->op == constants::DHCP_OP_REPLY)
                                {
                                    if (msg_type == constants::DHCP_MSG_OFFER || msg_type == 0x00)
                                    {
                                        globals::my_ip = dhcp->yiaddr;
                                        globals::dhcp_server_ip = dhcp->siaddr;
                                        if (globals::dhcp_server_ip == 0x00)
                                            globals::dhcp_server_ip = ip->saddr;
                                        dhcp_state = constants::DHCP_STATE_OFFER_RCVD;
                                        timeout = 0x00;
                                    }
                                }
                                else if (dhcp_state == constants::DHCP_STATE_OFFER_RCVD && dhcp->op == constants::DHCP_OP_REPLY)
                                {
                                    if (msg_type == constants::DHCP_MSG_ACK || msg_type == 0x00)
                                    {
                                        if (globals::router_ip == 0x00)
                                            globals::router_ip = globals::dhcp_server_ip;
                                        dhcp_state = constants::DHCP_STATE_BOUND;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (st == EFI_NOT_READY)
            {
                globals::bs->Stall(constants::STALL_1MS);
                if (timeout > 0x00) timeout--;
            }
            loops++;
        }

        if (dhcp_state != constants::DHCP_STATE_BOUND)
            return EFI_TIMEOUT;

        // --- ARP: Resolve the default gateway ---
        globals::arp_resolved = FALSE;
        timeout = 0x00;
        loops = 0x00;
        globals::arp_target_ip = globals::router_ip;

        while (!globals::arp_resolved)
        {
            if (loops >= constants::TIMEOUT_ARP_LOOPS) break;
            if (timeout == 0x00)
            {
                protocols::arp_request(globals::router_ip);
                timeout = constants::TIMEOUT_RETRANSMIT;
            }
            core::poll();
            globals::bs->Stall(constants::STALL_1MS);
            if (timeout > 0x00) timeout--;
            loops++;
        }

        if (!globals::arp_resolved)
            return EFI_TIMEOUT;

        return EFI_SUCCESS;
    }

    // =================================================================
    //  Network Initialization — Static IP
    // =================================================================

    /**
     * @brief Initialize the network stack with a static IP configuration.
     *
     * Skips DHCP entirely. The caller provides IP, gateway, subnet mask,
     * and DNS server. Still performs ARP to resolve the gateway MAC.
     *
     * @param ip       Local IPv4 address (network byte order).
     * @param gateway  Default gateway IP (network byte order).
     * @param mask     Subnet mask (network byte order).
     * @param dns      DNS server IP (network byte order, 0 = use Google 8.8.8.8).
     * @return         EFI_SUCCESS or an error code.
     */
    static EFI_STATUS init_network_static(UINT32 ip, UINT32 gateway, UINT32 mask, UINT32 dns)
    {
        rng::init();

        // Allocate buffers
        EFI_PHYSICAL_ADDRESS phys_rx = 0xFFFFFFFF;
        EFI_PHYSICAL_ADDRESS phys_tx = 0xFFFFFFFF;

        if (EFI_ERROR(globals::bs->AllocatePages(AllocateMaxAddress, EfiBootServicesData, 0x01, &phys_rx)))
            return EFI_OUT_OF_RESOURCES;
        if (EFI_ERROR(globals::bs->AllocatePages(AllocateMaxAddress, EfiBootServicesData, 0x01, &phys_tx)))
            return EFI_OUT_OF_RESOURCES;

        globals::rx_pkt = (UINT8*)(UINTN)phys_rx;
        globals::tx_pkt = (UINT8*)(UINTN)phys_tx;

        // Locate and open SNP
        EFI_GUID snp_guid = EFI_SIMPLE_NETWORK_PROTOCOL_GUID;
        UINTN handle_count = 0x00;
        EFI_HANDLE* handles = nullptr;
        EFI_STATUS status = globals::bs->LocateHandleBuffer(ByProtocol, &snp_guid, nullptr, &handle_count, &handles);

        if (EFI_ERROR(status) || handle_count == 0x00)
            return EFI_ERROR(status) ? status : EFI_NOT_FOUND;

        status = globals::bs->OpenProtocol(handles[0x00], &snp_guid, (VOID**)&globals::snp,
                                           globals::image_handle, nullptr, EFI_OPEN_PROTOCOL_EXCLUSIVE);
        if (EFI_ERROR(status))
        {
            globals::bs->DisconnectController(handles[0x00], nullptr, nullptr);
            status = globals::bs->OpenProtocol(handles[0x00], &snp_guid, (VOID**)&globals::snp,
                                               globals::image_handle, nullptr, EFI_OPEN_PROTOCOL_EXCLUSIVE);
            if (EFI_ERROR(status)) return status;
        }

        if (globals::snp->Mode->State == EfiSimpleNetworkStarted)
            globals::snp->Stop(globals::snp);

        globals::bs->Stall(constants::STALL_10MS);
        globals::snp->Start(globals::snp);
        globals::bs->Stall(constants::STALL_10MS);
        globals::snp->Initialize(globals::snp, 0x00, 0x00);
        globals::snp->ReceiveFilters(globals::snp,
            constants::SNP_FILTER_UNICAST | constants::SNP_FILTER_BROADCAST | constants::SNP_FILTER_ALL_MULTI,
            0x00, FALSE, 0x00, nullptr);
        memory::local_mem_cpy(globals::my_mac.Addr, globals::snp->Mode->CurrentAddress.Addr, constants::ETH_ALEN);

        // Apply static configuration
        globals::my_ip = ip;
        globals::router_ip = gateway;
        globals::subnet_mask = mask;
        globals::dns_server_ip = dns;

        // ARP resolve gateway
        globals::arp_resolved = FALSE;
        globals::arp_target_ip = globals::router_ip;
        UINT32 timeout = 0x00;
        UINT32 loops = 0x00;

        while (!globals::arp_resolved)
        {
            if (loops >= constants::TIMEOUT_ARP_LOOPS) break;
            if (timeout == 0x00)
            {
                protocols::arp_request(globals::router_ip);
                timeout = constants::TIMEOUT_RETRANSMIT;
            }
            core::poll();
            globals::bs->Stall(constants::STALL_1MS);
            if (timeout > 0x00) timeout--;
            loops++;
        }

        return globals::arp_resolved ? EFI_SUCCESS : EFI_TIMEOUT;
    }

    // =================================================================
    //  DNS Resolution
    // =================================================================

    /**
     * @brief Resolve a hostname to an IPv4 address via DNS.
     * @param hostname  Null-terminated ASCII hostname.
     * @param out_ip    Output: resolved IPv4 address (network byte order).
     * @return          EFI_SUCCESS or EFI_TIMEOUT.
     */
    static EFI_STATUS resolve_hostname(const CHAR8* hostname, UINT32* out_ip)
    {
        globals::dns_resolved = FALSE;
        globals::dns_resolved_ip = 0x00;
        UINT32 timeout = 0x00;
        UINT32 loops = 0x00;

        while (!globals::dns_resolved)
        {
            if (loops >= constants::TIMEOUT_TCP_LOOPS) break;
            if (timeout == 0x00)
            {
                protocols::dns_query(hostname);
                timeout = constants::TIMEOUT_RETRANSMIT;
            }
            core::poll();
            globals::bs->Stall(constants::STALL_1MS);
            if (timeout > 0x00) timeout--;
            loops++;
        }

        if (globals::dns_resolved)
        {
            *out_ip = globals::dns_resolved_ip;
            return EFI_SUCCESS;
        }
        return EFI_TIMEOUT;
    }

    // =================================================================
    //  TCP Client
    // =================================================================

    /**
     * @brief Establish a TCP connection (3-way handshake).
     * @param ip    Remote IPv4 address (network byte order).
     * @param port  Remote port number (host byte order).
     * @return      EFI_SUCCESS or EFI_TIMEOUT.
     */
    static EFI_STATUS tcp_connect(UINT32 ip, UINT16 port)
    {
        globals::tcp_remote_ip = ip;
        globals::tcp_remote_port = port;
        globals::tcp_local_port = rng::get_ephemeral_port();
        globals::tcp_seq = rng::get_u32();
        globals::tcp_ack = 0x00;
        globals::tcp_state = constants::TCP_STATE_SYN_SENT;

        UINT32 timeout = 0x00;
        UINT32 loops = 0x00;

        while (globals::tcp_state != constants::TCP_STATE_ESTABLISHED)
        {
            if (loops >= constants::TIMEOUT_TCP_LOOPS) break;
            if (globals::tcp_state == constants::TCP_STATE_CLOSED) break;  // RST received

            if (timeout == 0x00)
            {
                core::send_tcp_internal(constants::TCP_FLAG_SYN, globals::tcp_seq, globals::tcp_ack, nullptr, 0x00);
                timeout = constants::TIMEOUT_RETRANSMIT;
            }
            core::poll();
            globals::bs->Stall(constants::STALL_1MS);
            if (timeout > 0x00) timeout--;
            loops++;
        }

        return (globals::tcp_state == constants::TCP_STATE_ESTABLISHED) ? EFI_SUCCESS : EFI_TIMEOUT;
    }

    /**
     * @brief Send data over an established TCP connection.
     * @param data  Pointer to the data buffer.
     * @param len   Number of bytes to send.
     * @return      EFI_SUCCESS or EFI_NOT_READY if not connected.
     */
    static EFI_STATUS tcp_send(const VOID* data, UINTN len)
    {
        if (globals::tcp_state != constants::TCP_STATE_ESTABLISHED)
            return EFI_NOT_READY;

        core::send_tcp_internal(constants::TCP_FLAG_PSH_ACK, globals::tcp_seq, globals::tcp_ack, (const UINT8*)data, len);
        globals::tcp_seq += len;
        return EFI_SUCCESS;
    }

    /**
     * @brief Receive data from an established TCP connection.
     * @param buffer      Output buffer.
     * @param max_len     Maximum bytes to receive.
     * @param actual_len  Output: actual bytes received.
     * @param timeout_ms  Timeout in milliseconds.
     * @return            EFI_SUCCESS or EFI_TIMEOUT.
     */
    static EFI_STATUS tcp_receive(VOID* buffer, UINTN max_len, UINTN* actual_len, UINT32 timeout_ms)
    {
        globals::tcp_rx_buffer = (UINT8*)buffer;
        globals::tcp_rx_max_len = max_len;
        globals::tcp_rx_current_len = 0x00;
        globals::tcp_rx_done = FALSE;

        UINT32 loops = 0x00;
        UINT32 max_loops = timeout_ms * 0x0A;
        while (!globals::tcp_rx_done)
        {
            if (loops >= max_loops) break;
            if (globals::tcp_state == constants::TCP_STATE_CLOSED ||
                globals::tcp_state == constants::TCP_STATE_CLOSED_DONE) break;
            core::poll();
            globals::bs->Stall(constants::STALL_100US);
            loops++;
        }

        globals::tcp_rx_buffer = nullptr;
        *actual_len = globals::tcp_rx_current_len;
        return globals::tcp_rx_done ? EFI_SUCCESS : EFI_TIMEOUT;
    }

    /**
     * @brief Gracefully close the TCP connection (FIN handshake).
     * @return EFI_SUCCESS.
     */
    static EFI_STATUS tcp_close()
    {
        if (globals::tcp_state == constants::TCP_STATE_ESTABLISHED)
        {
            core::send_tcp_internal(constants::TCP_FLAG_FIN_ACK, globals::tcp_seq, globals::tcp_ack, nullptr, 0x00);
            globals::tcp_state = constants::TCP_STATE_FIN_WAIT;

            // Drain remaining packets for a short while
            UINT32 loops = 0x00;
            while (globals::tcp_state != constants::TCP_STATE_CLOSED_DONE)
            {
                if (loops >= constants::TIMEOUT_CLOSE_LOOPS) break;
                core::poll();
                globals::bs->Stall(constants::STALL_1MS);
                loops++;
            }
        }

        globals::tcp_local_port = 0x00;
        globals::tcp_state = constants::TCP_STATE_CLOSED;
        return EFI_SUCCESS;
    }

    // =================================================================
    //  UDP
    // =================================================================

    /**
     * @brief Send a UDP datagram.
     * @param dest_ip    Destination IP (network byte order).
     * @param dest_port  Destination port (host byte order).
     * @param data       Payload data.
     * @param len        Payload length.
     * @return           EFI_SUCCESS.
     */
    static EFI_STATUS udp_send(UINT32 dest_ip, UINT16 dest_port, const VOID* data, UINTN len)
    {
        if (globals::udp_local_port == 0x00)
            globals::udp_local_port = rng::get_ephemeral_port();

        core::send_udp(dest_ip, dest_port, globals::udp_local_port, (const UINT8*)data, len);
        return EFI_SUCCESS;
    }

    /**
     * @brief Receive a UDP datagram.
     * @param buffer      Output buffer.
     * @param max_len     Maximum bytes to receive.
     * @param actual_len  Output: actual bytes received.
     * @param timeout_ms  Timeout in milliseconds.
     * @return            EFI_SUCCESS or EFI_TIMEOUT.
     */
    static EFI_STATUS udp_receive(VOID* buffer, UINTN max_len, UINTN* actual_len, UINT32 timeout_ms)
    {
        globals::udp_rx_buffer = (UINT8*)buffer;
        globals::udp_rx_max_len = max_len;
        globals::udp_rx_current_len = 0x00;
        globals::udp_rx_done = FALSE;

        UINT32 loops = 0x00;
        UINT32 max_loops = timeout_ms * 0x0A;
        while (!globals::udp_rx_done)
        {
            if (loops >= max_loops) break;
            core::poll();
            globals::bs->Stall(constants::STALL_100US);
            loops++;
        }

        globals::udp_rx_buffer = nullptr;
        *actual_len = globals::udp_rx_current_len;
        return globals::udp_rx_done ? EFI_SUCCESS : EFI_TIMEOUT;
    }

    // =================================================================
    //  ICMP Ping
    // =================================================================

    /**
     * @brief Send an ICMP Echo Request and wait for a reply.
     * @param target_ip   Destination IP (network byte order).
     * @param timeout_ms  Timeout in milliseconds.
     * @return            EFI_SUCCESS if reply received, EFI_TIMEOUT otherwise.
     */
    static EFI_STATUS ping(UINT32 target_ip, UINT32 timeout_ms)
    {
        globals::ping_id = rng::get_u32() & 0xFFFF;
        globals::ping_seq = rng::get_u32() & 0xFFFF;
        globals::ping_reply_received = FALSE;

        core::send_icmp_echo(target_ip, globals::ping_id, globals::ping_seq);

        UINT32 loops = 0x00;
        UINT32 max_loops = timeout_ms * 0x0A;
        while (!globals::ping_reply_received)
        {
            if (loops >= max_loops) break;
            core::poll();
            globals::bs->Stall(constants::STALL_100US);
            loops++;
        }

        return globals::ping_reply_received ? EFI_SUCCESS : EFI_TIMEOUT;
    }

    // =================================================================
    //  HTTP GET
    // =================================================================

    /**
     * @brief Perform an HTTP/1.1 GET request.
     *
     * Resolves the hostname via DNS, connects via TCP on port 80,
     * sends the GET request with Host header, and receives the response.
     *
     * @param hostname         Server hostname (e.g. "example.com").
     * @param path             Request path (e.g. "/index.html").
     * @param response_buffer  Output buffer for the HTTP response.
     * @param max_len          Maximum response size.
     * @param actual_len       Output: actual bytes received.
     * @return                 EFI_SUCCESS or an error code.
     */
    static EFI_STATUS http_get(const CHAR8* hostname, const CHAR8* path, VOID* response_buffer, UINTN max_len, UINTN* actual_len)
    {
        // Resolve hostname
        UINT32 target_ip = 0x00;
        EFI_STATUS st = resolve_hostname(hostname, &target_ip);
        if (EFI_ERROR(st)) return st;

        // Connect to port 80
        st = tcp_connect(target_ip, 0x50);
        if (EFI_ERROR(st)) return st;

        // Build HTTP request: GET <path> HTTP/1.1\r\nHost: <hostname>\r\nConnection: close\r\n\r\n
        CHAR8 req[constants::HTTP_REQ_SIZE];
        memory::local_zero_mem(req, sizeof(req));

        const CHAR8* parts[] = { "GET ", path, " HTTP/1.1\r\nHost: ", hostname, "\r\nConnection: close\r\n\r\n" };
        UINTN offset = 0x00;
        for (UINTN i = 0x00; i < 0x05; i++)
        {
            const CHAR8* p = parts[i];
            while (*p != 0x00 && offset < sizeof(req) - 0x01)
            {
                req[offset++] = *p++;
            }
        }

        st = tcp_send(req, offset);
        if (EFI_ERROR(st))
        {
            tcp_close();
            return st;
        }

        st = tcp_receive(response_buffer, max_len, actual_len, 0x1388);
        tcp_close();
        return st;
    }
}