/**
 * @file example_static_ip.cpp
 * @brief Example: Initialize the network with a static IP (no DHCP).
 *
 * Demonstrates init_network_static() for environments where DHCP is
 * unavailable. The user provides IP, gateway, subnet mask, and DNS.
 *
 * NOTE: Adjust the addresses below to match your network.
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/SimpleNetwork.h>

#include "../types.hpp"
#include "../constants.hpp"
#include "../globals.hpp"
#include "../memory.hpp"
#include "../utils.hpp"
#include "../rng.hpp"
#include "../io.hpp"
#include "../net_math.hpp"
#include "../arp_cache.hpp"
#include "../icmp.hpp"
#include "../protocols.hpp"
#include "../core.hpp"
#include "../api.hpp"

extern "C" void __chkstk(void) { return; }

extern "C" EFI_STATUS EFIAPI EfiMain(IN EFI_HANDLE image_handle, IN EFI_SYSTEM_TABLE* system_table)
{
    globals::bs = system_table->BootServices;
    globals::st = system_table;
    globals::rt = system_table->RuntimeServices;
    globals::image_handle = image_handle;

    io::print_str(L"\r\n=== Example: Static IP Configuration ===\r\n\r\n");

    // --- Configure your static addresses here ---
    // utils::make_ipv4(a, b, c, d) builds an IP in network byte order
    UINT32 my_ip   = utils::make_ipv4(192, 168, 1, 200);
    UINT32 gateway = utils::make_ipv4(192, 168, 1, 1);
    UINT32 mask    = utils::make_ipv4(255, 255, 255, 0);
    UINT32 dns     = utils::make_ipv4(8, 8, 8, 8);

    io::print_str(L"[*] Configuring static IP...\r\n");
    io::print_str(L"  IP      : ");  io::print_ip(my_ip);   io::print_str(L"\r\n");
    io::print_str(L"  Gateway : ");  io::print_ip(gateway);  io::print_str(L"\r\n");
    io::print_str(L"  Mask    : ");  io::print_ip(mask);     io::print_str(L"\r\n");
    io::print_str(L"  DNS     : ");  io::print_ip(dns);      io::print_str(L"\r\n\r\n");

    EFI_STATUS st = api::init_network_static(my_ip, gateway, mask, dns);

    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Static init failed (ARP timeout?): ");
        io::print_hex((UINT64)st);
        io::print_str(L"\r\n");
        return st;
    }

    io::print_str(L"[+] Network ready with static IP!\r\n");
    io::print_str(L"[+] Gateway MAC: ");
    io::print_mac(globals::router_mac);
    io::print_str(L"\r\n\r\n");

    // --- Test connectivity with a ping ---
    io::print_str(L"[*] Pinging gateway...\r\n");
    st = api::ping(gateway, 3000);
    if (!EFI_ERROR(st))
        io::print_str(L"[+] Gateway is reachable!\r\n");
    else
        io::print_str(L"[-] Ping timeout.\r\n");

    // --- Test DNS ---
    io::print_str(L"\r\n[*] Resolving google.com...\r\n");
    UINT32 resolved = 0;
    st = api::resolve_hostname("google.com", &resolved);
    if (!EFI_ERROR(st))
    {
        io::print_str(L"[+] google.com -> ");
        io::print_ip(resolved);
        io::print_str(L"\r\n");
    }
    else
    {
        io::print_str(L"[-] DNS failed.\r\n");
    }

    io::print_str(L"\r\n[*] Done.\r\n");
    return EFI_SUCCESS;
}
