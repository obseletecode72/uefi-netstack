/**
 * @file example_ping.cpp
 * @brief Example: ICMP Ping a target IP address.
 *
 * Sends an ICMP Echo Request to the default gateway and reports
 * whether a reply was received. Useful for connectivity testing.
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

    io::print_str(L"\r\n=== Example: ICMP Ping ===\r\n\r\n");

    EFI_STATUS st = api::init_network();
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Network init failed.\r\n");
        return st;
    }

    io::print_str(L"[+] Network ready. IP: ");
    io::print_ip(globals::my_ip);
    io::print_str(L"\r\n\r\n");

    // Ping the default gateway 5 times
    for (UINTN i = 0; i < 5; i++)
    {
        io::print_str(L"[*] Ping ");
        io::print_ip(globals::router_ip);
        io::print_str(L" #");
        io::print_dec(i + 1);
        io::print_str(L" ... ");

        st = api::ping(globals::router_ip, 3000);  // 3 second timeout

        if (!EFI_ERROR(st))
        {
            io::print_str(L"Reply received!\r\n");
        }
        else
        {
            io::print_str(L"Timeout.\r\n");
        }

        globals::bs->Stall(1000000);  // 1 second between pings
    }

    io::print_str(L"\r\n[*] Done.\r\n");
    return EFI_SUCCESS;
}
