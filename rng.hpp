#pragma once

/**
 * @file rng.hpp
 * @brief Simple PRNG seeded from the EFI Real-Time Clock.
 */

namespace rng
{
    /// Seed the PRNG from EFI RTC.
    static VOID init()
    {
        if (globals::rt != nullptr)
        {
            EFI_TIME t;
            globals::rt->GetTime(&t, nullptr);
            globals::rng_seed = t.Second | (t.Minute << 0x06) | (t.Hour << 0x0C) | (t.Day << 0x11) | (t.Year << 0x16);
        }
    }

    /// Generate a pseudo-random 32-bit value.
    static UINT32 get_u32()
    {
        globals::rng_seed = (globals::rng_seed * 0x41C64E6D + 0x3039) % 0x7FFFFFFF;
        return globals::rng_seed;
    }

    /// Generate a random ephemeral port (49152-65535).
    static UINT16 get_ephemeral_port()
    {
        return constants::EPHEMERAL_PORT_BASE + (get_u32() % constants::EPHEMERAL_PORT_RANGE);
    }
}