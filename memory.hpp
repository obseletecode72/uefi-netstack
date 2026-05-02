#pragma once

/**
 * @file memory.hpp
 * @brief Freestanding memory utilities (no CRT dependency).
 *
 * Provides memset-zero and memcpy equivalents that compile without any
 * runtime library. Uses volatile writes in local_zero_mem to prevent
 * the compiler from optimising away security-sensitive clears.
 */

namespace memory
{
    /**
     * @brief Zero-fill a buffer.
     * @param buf   Pointer to the buffer.
     * @param size  Number of bytes to zero.
     * @return      The original buffer pointer.
     */
    static VOID* local_zero_mem(VOID* buf, UINTN size)
    {
        volatile UINT8* p = (UINT8*)buf;
        while (size > 0x00)
        {
            *p = 0x00;
            p++;
            size--;
        }
        return buf;
    }

    /**
     * @brief Copy bytes from source to destination.
     * @param dest  Destination buffer.
     * @param src   Source buffer.
     * @param size  Number of bytes to copy.
     * @return      The destination pointer.
     */
    static VOID* local_mem_cpy(VOID* dest, const VOID* src, UINTN size)
    {
        volatile UINT8* d = (UINT8*)dest;
        const UINT8* s = (const UINT8*)src;
        while (size > 0x00)
        {
            *d = *s;
            d++;
            s++;
            size--;
        }
        return dest;
    }

    /**
     * @brief Compare two memory regions byte-by-byte.
     * @param m1   First memory region.
     * @param m2   Second memory region.
     * @param len  Number of bytes to compare.
     * @return     0 if equal, positive if m1 > m2, negative if m1 < m2.
     */
    static INT32 local_mem_cmp(const VOID* m1, const VOID* m2, UINTN len)
    {
        const UINT8* p1 = (const UINT8*)m1;
        const UINT8* p2 = (const UINT8*)m2;
        while (len > 0x00)
        {
            if (*p1 != *p2)
            {
                return (INT32)*p1 - (INT32)*p2;
            }
            p1++;
            p2++;
            len--;
        }
        return 0;
    }
}
