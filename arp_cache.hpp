#pragma once

/**
 * @file arp_cache.hpp
 * @brief Simple fixed-size ARP cache (IP -> MAC mapping).
 *
 * Stores up to ARP_CACHE_SIZE entries. Uses linear scan with
 * round-robin eviction when full. Avoids redundant ARP requests
 * for recently resolved addresses.
 */

namespace arp_cache
{
    struct entry
    {
        UINT32  ip;
        UINT8   mac[0x06];
        BOOLEAN valid;
    };

    static entry table[constants::ARP_CACHE_SIZE] = {};
    static UINTN next_slot = 0x00;

    /// Look up a MAC address by IP. Returns TRUE if found.
    static BOOLEAN lookup(UINT32 ip, UINT8* out_mac)
    {
        for (UINTN i = 0x00; i < constants::ARP_CACHE_SIZE; i++)
        {
            if (table[i].valid && table[i].ip == ip)
            {
                memory::local_mem_cpy(out_mac, table[i].mac, constants::ETH_ALEN);
                return TRUE;
            }
        }
        return FALSE;
    }

    /// Insert or update an ARP cache entry.
    static VOID update(UINT32 ip, const UINT8* mac)
    {
        // Update existing entry if present
        for (UINTN i = 0x00; i < constants::ARP_CACHE_SIZE; i++)
        {
            if (table[i].valid && table[i].ip == ip)
            {
                memory::local_mem_cpy(table[i].mac, mac, constants::ETH_ALEN);
                return;
            }
        }

        // Insert into next slot (round-robin eviction)
        table[next_slot].ip = ip;
        memory::local_mem_cpy(table[next_slot].mac, mac, constants::ETH_ALEN);
        table[next_slot].valid = TRUE;
        next_slot = (next_slot + 0x01) % constants::ARP_CACHE_SIZE;
    }

    /// Clear all entries.
    static VOID flush()
    {
        for (UINTN i = 0x00; i < constants::ARP_CACHE_SIZE; i++)
        {
            table[i].valid = FALSE;
        }
        next_slot = 0x00;
    }
}
