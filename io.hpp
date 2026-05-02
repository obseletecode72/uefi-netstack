#pragma once

/**
 * @file io.hpp
 * @brief Console output helpers for EFI environment.
 *
 * Provides formatted printing: strings, decimal/hex integers, IPv4
 * addresses, MAC addresses, and raw ASCII buffers with CR/LF handling.
 */

namespace io
{
    /// Print a wide string to EFI ConOut.
    static VOID print_str(const unsigned short* str)
    {
        if (globals::st != nullptr && globals::st->ConOut != nullptr)
        {
            globals::st->ConOut->OutputString(globals::st->ConOut, (CHAR16*)(str));
        }
    }

    /// Print a UINT64 as a decimal number.
    static VOID print_dec(UINT64 val)
    {
        unsigned short buf[0x16];
        unsigned short tmp[0x16];
        UINTN i = 0x00;

        if (val == 0x00)
        {
            print_str(L"0");
            return;
        }

        while (val > 0x00)
        {
            tmp[i] = (unsigned short)(L'0' + val % 0x0A);
            i++;
            val /= 0x0A;
        }

        for (UINTN j = 0x00; j < i; j++)
        {
            buf[j] = tmp[i - 0x01 - j];
        }

        buf[i] = L'\0';
        print_str(buf);
    }

    /// Print a UINT64 as a hexadecimal number with "0x" prefix.
    static VOID print_hex(UINT64 val)
    {
        unsigned short buf[0x14];
        unsigned short tmp[0x14];
        UINTN i = 0x00;

        if (val == 0x00)
        {
            print_str(L"0x0");
            return;
        }

        while (val > 0x00)
        {
            UINT64 d = val & 0x0F;
            tmp[i] = (unsigned short)(d < 0x0A ? L'0' + d : L'A' + d - 0x0A);
            i++;
            val >>= 0x04;
        }

        buf[0x00] = L'0';
        buf[0x01] = L'x';
        for (UINTN j = 0x00; j < i; j++)
        {
            buf[0x02 + j] = tmp[i - 0x01 - j];
        }
        buf[0x02 + i] = L'\0';
        print_str(buf);
    }

    /// Print an IPv4 address in dotted-decimal notation (network byte order).
    static VOID print_ip(UINT32 ip)
    {
        print_dec(ip & 0xFF);
        print_str(L".");
        print_dec((ip >> 0x08) & 0xFF);
        print_str(L".");
        print_dec((ip >> 0x10) & 0xFF);
        print_str(L".");
        print_dec((ip >> 0x18) & 0xFF);
    }

    /// Print a MAC address in XX:XX:XX:XX:XX:XX format.
    static VOID print_mac(const UINT8* mac)
    {
        for (UINTN i = 0x00; i < constants::ETH_ALEN; i++)
        {
            if (i > 0x00) print_str(L":");
            UINT8 hi = (mac[i] >> 0x04) & 0x0F;
            UINT8 lo = mac[i] & 0x0F;
            unsigned short c[0x03];
            c[0x00] = (unsigned short)(hi < 0x0A ? L'0' + hi : L'A' + hi - 0x0A);
            c[0x01] = (unsigned short)(lo < 0x0A ? L'0' + lo : L'A' + lo - 0x0A);
            c[0x02] = L'\0';
            print_str(c);
        }
    }

    /// Print an EFI_STATUS value with a descriptive label.
    static VOID print_status(const unsigned short* label, EFI_STATUS status)
    {
        print_str(label);
        print_str(L" Status: ");
        print_hex((UINT64)status);
        print_str(L"\r\n");
    }

    /// Print an ASCII buffer of known length, inserting CR before bare LF.
    static VOID print_ascii_n(const CHAR8* str, UINTN len)
    {
        if (str == nullptr) return;

        unsigned short c[0x02] = { 0x00, 0x00 };
        for (UINTN i = 0x00; i < len; i++)
        {
            c[0x00] = (unsigned short)str[i];
            if (c[0x00] == 0x0A)
            {
                if (i == 0x00 || str[i - 0x01] != 0x0D)
                {
                    unsigned short cr[0x02] = { 0x0D, 0x00 };
                    print_str(cr);
                }
            }
            print_str(c);
        }
    }
}
