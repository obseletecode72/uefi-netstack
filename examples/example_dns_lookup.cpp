/**
 * @file example_dns_lookup.cpp
 * @brief Example: Resolve multiple hostnames via DNS.
 *
 * Demonstrates the DNS resolution API by looking up several
 * well-known hostnames and printing their IPv4 addresses.
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

    io::print_str(L"\r\n=== Example: DNS Lookup ===\r\n\r\n");

    EFI_STATUS st = api::init_network();
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Network init failed.\r\n");
        return st;
    }

    io::print_str(L"[+] DNS Server: ");
    io::print_ip(globals::dns_server_ip);
    io::print_str(L"\r\n\r\n");

    // List of hostnames to resolve
    const CHAR8* hosts[] = {
        "example.com",
        "google.com",
        "github.com",
        "cloudflare.com"
    };
    const unsigned short* labels[] = {
        L"example.com",
        L"google.com",
        L"github.com",
        L"cloudflare.com"
    };

    for (UINTN i = 0; i < 4; i++)
    {
        UINT32 ip = 0;
        io::print_str(L"  ");
        io::print_str(labels[i]);
        io::print_str(L" -> ");

        st = api::resolve_hostname(hosts[i], &ip);
        if (!EFI_ERROR(st))
        {
            io::print_ip(ip);
        }
        else
        {
            io::print_str(L"FAILED");
        }
        io::print_str(L"\r\n");
    }

    io::print_str(L"\r\n[*] Done.\r\n");
    return EFI_SUCCESS;
}
