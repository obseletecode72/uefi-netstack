/**
 * @file example_http_get.cpp
 * @brief Example: Fetch a webpage via HTTP GET.
 *
 * Demonstrates the simplest use case of the network stack:
 * initialize via DHCP and perform an HTTP/1.1 GET request.
 *
 * Usage: Replace the hostname and path to fetch any HTTP resource.
 *        Note: HTTPS is NOT supported (no TLS implementation).
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

    io::print_str(L"\r\n=== Example: HTTP GET ===\r\n\r\n");

    // Step 1: Initialize network via DHCP
    EFI_STATUS st = api::init_network();
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Network init failed.\r\n");
        return st;
    }

    io::print_str(L"[+] IP: ");
    io::print_ip(globals::my_ip);
    io::print_str(L"\r\n\r\n");

    // Step 2: Perform HTTP GET
    UINT8 response[0x1000];
    memory::local_zero_mem(response, sizeof(response));
    UINTN len = 0x00;

    io::print_str(L"[*] GET http://example.com/ ...\r\n");
    st = api::http_get("example.com", "/", response, sizeof(response) - 1, &len);

    if (!EFI_ERROR(st) && len > 0x00)
    {
        io::print_str(L"\r\n");
        io::print_ascii_n((CHAR8*)response, len);
        io::print_str(L"\r\n\r\n[+] Received ");
        io::print_dec(len);
        io::print_str(L" bytes.\r\n");
    }
    else
    {
        io::print_str(L"[-] Request failed.\r\n");
    }

    return EFI_SUCCESS;
}
