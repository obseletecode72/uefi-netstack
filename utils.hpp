#pragma once

/**
 * @file utils.hpp
 * @brief Byte-order conversion and string utilities.
 *
 * Provides host↔network byte order helpers (htons/htonl/ntohs/ntohl),
 * ASCII string length, and memory comparison functions used throughout
 * the stack.
 */

namespace utils
{
    /// @brief Host-to-network byte order for 16-bit values.
    static UINT16 htons(UINT16 x)
    {
        return (UINT16)((((UINT16)(x) & 0xFF00) >> 0x08) |
                        (((UINT16)(x) & 0x00FF) << 0x08));
    }

    /// @brief Host-to-network byte order for 32-bit values.
    static UINT32 htonl(UINT32 x)
    {
        return (UINT32)((((UINT32)(x) & 0xFF000000) >> 0x18) |
                        (((UINT32)(x) & 0x00FF0000) >> 0x08) |
                        (((UINT32)(x) & 0x0000FF00) << 0x08) |
                        (((UINT32)(x) & 0x000000FF) << 0x18));
    }

    /// @brief Network-to-host byte order for 16-bit values.
    static UINT16 ntohs(UINT16 x) { return htons(x); }

    /// @brief Network-to-host byte order for 32-bit values.
    static UINT32 ntohl(UINT32 x) { return htonl(x); }

    /**
     * @brief Calculate the length of a null-terminated ASCII string.
     * @param s  Pointer to the string.
     * @return   Number of characters before the null terminator.
     */
    static UINTN ascii_str_len(const CHAR8* s)
    {
        UINTN len = 0x00;
        while (s[len] != 0x00)
        {
            len++;
        }
        return len;
    }

    /**
     * @brief Compare two memory regions for equality.
     * @param m1   First region.
     * @param m2   Second region.
     * @param len  Number of bytes to compare.
     * @return     TRUE if identical, FALSE otherwise.
     */
    static BOOLEAN mem_cmp(const VOID* m1, const VOID* m2, UINTN len)
    {
        const UINT8* p1 = (const UINT8*)m1;
        const UINT8* p2 = (const UINT8*)m2;
        while (len > 0x00)
        {
            if (*p1 != *p2)
            {
                return FALSE;
            }
            p1++;
            p2++;
            len--;
        }
        return TRUE;
    }

    /**
     * @brief Build a dotted-decimal IPv4 address from four octets.
     *        Result is in network byte order (little-endian on x64 EFI).
     * @return UINT32 IPv4 address in network byte order.
     */
    static UINT32 make_ipv4(UINT8 a, UINT8 b, UINT8 c, UINT8 d)
    {
        return (UINT32)a | ((UINT32)b << 0x08) | ((UINT32)c << 0x10) | ((UINT32)d << 0x18);
    }
}