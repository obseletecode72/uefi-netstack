#pragma once

/**
 * @file net_math.hpp
 * @brief Internet checksum algorithms (RFC 1071).
 *
 * Implements the standard one's-complement checksum used by IPv4, TCP,
 * UDP, and ICMP. Also provides the pseudo-header variant required by
 * TCP and UDP for their transport-layer checksums.
 */

namespace net_math
{
    /**
     * @brief Compute the Internet checksum (one's complement of one's complement sum).
     * @param data  Pointer to the data to checksum.
     * @param len   Length in bytes.
     * @return      16-bit checksum in network byte order.
     */
    static UINT16 checksum(VOID* data, UINTN len)
    {
        UINT32 sum = 0x00;
        UINT16* ptr = (UINT16*)data;

        while (len > 0x01)
        {
            sum += *ptr;
            ptr++;
            len -= 0x02;
        }

        if (len == 0x01)
        {
            sum += *(UINT8*)ptr;
        }

        while ((sum >> 0x10) > 0x00)
        {
            sum = (sum & 0xFFFF) + (sum >> 0x10);
        }

        return (UINT16)~sum;
    }

    /**
     * @brief Compute TCP/UDP checksum including the IPv4 pseudo-header.
     * @param saddr   Source IP (network byte order).
     * @param daddr   Destination IP (network byte order).
     * @param proto   IP protocol number (6 = TCP, 17 = UDP).
     * @param data    Pointer to the TCP/UDP header + payload.
     * @param len     Length of the TCP/UDP segment in bytes.
     * @return        16-bit checksum in network byte order.
     */
    static UINT16 pseudo_checksum(UINT32 saddr, UINT32 daddr, UINT8 proto, VOID* data, UINT16 len)
    {
        UINT32 sum = 0x00;
        types::pseudo_hdr ph;

        ph.saddr = saddr;
        ph.daddr = daddr;
        ph.zero = 0x00;
        ph.protocol = proto;
        ph.tcp_length = utils::htons(len);

        UINT16* p = (UINT16*)&ph;
        for (UINTN i = 0x00; i < sizeof(types::pseudo_hdr) / 0x02; i++)
        {
            sum += p[i];
        }

        p = (UINT16*)data;
        UINTN l = len;

        while (l > 0x01)
        {
            sum += *p;
            p++;
            l -= 0x02;
        }

        if (l == 0x01)
        {
            sum += *(UINT8*)p;
        }

        while ((sum >> 0x10) > 0x00)
        {
            sum = (sum & 0xFFFF) + (sum >> 0x10);
        }

        return (UINT16)~sum;
    }
}
