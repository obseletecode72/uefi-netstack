/**
 * @file example_udp_echo.cpp
 * @brief Example: Send and receive UDP datagrams.
 *
 * Demonstrates the UDP API by sending a message to a UDP echo
 * server and printing the reply.
 *
 * For testing, run a UDP echo server on another machine:
 *   socat -v UDP-LISTEN:7777,fork PIPE
 *   or: nc -u -l -p 7777 (and type responses manually)
 *
 * NOTE: Change TARGET_IP to match your echo server's address.
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

    io::print_str(L"\r\n=== Example: UDP Echo ===\r\n\r\n");

    EFI_STATUS st = api::init_network();
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Network init failed.\r\n");
        return st;
    }

    io::print_str(L"[+] IP: ");
    io::print_ip(globals::my_ip);
    io::print_str(L"\r\n\r\n");

    // Configure target — change this to your echo server's IP
    // Example: 192.168.1.100 = utils::make_ipv4(192, 168, 1, 100)
    UINT32 target_ip = globals::router_ip;  // Default: ping the gateway
    UINT16 target_port = 7777;

    // Prepare UDP payload
    const CHAR8* message = "Hello from UEFI!";
    UINTN msg_len = utils::ascii_str_len(message);

    // Bind to an ephemeral port
    globals::udp_local_port = rng::get_ephemeral_port();

    io::print_str(L"[*] Sending UDP to ");
    io::print_ip(target_ip);
    io::print_str(L":");
    io::print_dec(target_port);
    io::print_str(L"\r\n");

    st = api::udp_send(target_ip, target_port, message, msg_len);
    io::print_str(L"[+] Sent ");
    io::print_dec(msg_len);
    io::print_str(L" bytes.\r\n");

    // Wait for a reply
    UINT8 reply[0x200];
    memory::local_zero_mem(reply, sizeof(reply));
    UINTN reply_len = 0;

    io::print_str(L"[*] Waiting for reply (5 sec timeout)...\r\n");
    st = api::udp_receive(reply, sizeof(reply) - 1, &reply_len, 5000);

    if (!EFI_ERROR(st) && reply_len > 0)
    {
        io::print_str(L"[+] Received ");
        io::print_dec(reply_len);
        io::print_str(L" bytes: ");
        io::print_ascii_n((CHAR8*)reply, reply_len);
        io::print_str(L"\r\n");
    }
    else
    {
        io::print_str(L"[-] No reply (timeout or server not running).\r\n");
    }

    io::print_str(L"\r\n[*] Done.\r\n");
    return EFI_SUCCESS;
}
