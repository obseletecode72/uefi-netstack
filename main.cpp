/**
 * @file main.cpp
 * @brief Entry point for the UEFI bare-metal network stack demonstration.
 *
 * This program demonstrates the full capability of the network stack:
 *  1. DHCP-based network initialization
 *  2. Network configuration display (IP, gateway, DNS, MAC, subnet)
 *  3. ICMP Ping to the default gateway
 *  4. DNS hostname resolution
 *  5. HTTP GET request to example.com
 *
 * Build: Visual Studio + EDK2 headers, output as bootx64.efi
 * Deploy: Copy to \EFI\BOOT\BOOTX64.EFI on a FAT32 USB drive
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SimpleNetwork.h>

#include "types.hpp"
#include "constants.hpp"
#include "globals.hpp"
#include "memory.hpp"
#include "utils.hpp"
#include "rng.hpp"
#include "io.hpp"
#include "net_math.hpp"
#include "arp_cache.hpp"
#include "icmp.hpp"
#include "protocols.hpp"
#include "core.hpp"
#include "api.hpp"

/// Required stub — CRT stack probe is not available in freestanding EFI.
extern "C" void __chkstk(void)
{
    return;
}

extern "C" EFI_STATUS EFIAPI EfiMain(IN EFI_HANDLE image_handle, IN EFI_SYSTEM_TABLE* system_table)
{
    // --- Store EFI service pointers ---
    globals::bs = system_table->BootServices;
    globals::st = system_table;
    globals::rt = system_table->RuntimeServices;
    globals::image_handle = image_handle;

    io::print_str(L"\r\n");
    io::print_str(L"========================================================\r\n");
    io::print_str(L"  UEFI Bare-Metal Network Stack v1.0\r\n");
    io::print_str(L"  IA made but it works i think...\r\n");
    io::print_str(L"========================================================\r\n\r\n");

    // ================================================================
    //  Step 1: Initialize the network via DHCP
    // ================================================================

    io::print_str(L"[*] Initializing network (DHCP)...\r\n");
    EFI_STATUS st = api::init_network();

    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Network initialization failed: ");
        io::print_hex((UINT64)st);
        io::print_str(L"\r\n");
        return st;
    }

    io::print_str(L"[+] Network initialized successfully!\r\n\r\n");

    // ================================================================
    //  Step 2: Display network configuration
    // ================================================================

    io::print_str(L"--- Network Configuration ---\r\n");

    io::print_str(L"  MAC Address : ");
    io::print_mac(globals::my_mac.Addr);
    io::print_str(L"\r\n");

    io::print_str(L"  IP Address  : ");
    io::print_ip(globals::my_ip);
    io::print_str(L"\r\n");

    io::print_str(L"  Subnet Mask : ");
    io::print_ip(globals::subnet_mask);
    io::print_str(L"\r\n");

    io::print_str(L"  Gateway     : ");
    io::print_ip(globals::router_ip);
    io::print_str(L"\r\n");

    io::print_str(L"  DNS Server  : ");
    io::print_ip(globals::dns_server_ip);
    io::print_str(L"\r\n");

    if (globals::dhcp_lease_time > 0x00)
    {
        io::print_str(L"  Lease Time  : ");
        io::print_dec(globals::dhcp_lease_time);
        io::print_str(L" seconds\r\n");
    }

    io::print_str(L"-----------------------------\r\n\r\n");

    // ================================================================
    //  Step 3: Ping the default gateway
    // ================================================================

    io::print_str(L"[*] Pinging gateway (");
    io::print_ip(globals::router_ip);
    io::print_str(L")...\r\n");

    st = api::ping(globals::router_ip, 0x0BB8);  // 3-second timeout

    if (!EFI_ERROR(st))
    {
        io::print_str(L"[+] Ping reply received!\r\n\r\n");
    }
    else
    {
        io::print_str(L"[-] Ping timeout (gateway may block ICMP)\r\n\r\n");
    }

    // ================================================================
    //  Step 4: DNS resolution
    // ================================================================

    io::print_str(L"[*] Resolving example.com...\r\n");

    UINT32 resolved_ip = 0x00;
    st = api::resolve_hostname("example.com", &resolved_ip);

    if (!EFI_ERROR(st))
    {
        io::print_str(L"[+] example.com -> ");
        io::print_ip(resolved_ip);
        io::print_str(L"\r\n\r\n");
    }
    else
    {
        io::print_str(L"[-] DNS resolution failed.\r\n\r\n");
    }

    // ================================================================
    //  Step 5: HTTP GET request
    // ================================================================

    io::print_str(L"[*] Fetching http://example.com/ ...\r\n");

    UINT8 rx_buf[0x1000];
    memory::local_zero_mem(rx_buf, sizeof(rx_buf));
    UINTN rx_len = 0x00;

    st = api::http_get("example.com", "/", rx_buf, sizeof(rx_buf) - 0x01, &rx_len);

    if (!EFI_ERROR(st) && rx_len > 0x00)
    {
        io::print_str(L"\r\n--- HTTP Response (");
        io::print_dec(rx_len);
        io::print_str(L" bytes) ---\r\n");
        io::print_ascii_n((CHAR8*)rx_buf, rx_len);
        io::print_str(L"\r\n--- End of Response ---\r\n");
    }
    else
    {
        io::print_str(L"[-] HTTP request failed.\r\n");
    }

    io::print_str(L"\r\n[*] Demo complete. Press reset to reboot.\r\n");
    return EFI_SUCCESS;
}
