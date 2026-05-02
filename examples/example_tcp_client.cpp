/**
 * @file example_tcp_client.cpp
 * @brief Example: Raw TCP client — connect, send, and receive.
 *
 * Connects to a TCP server, sends a custom message, and prints
 * whatever the server sends back. This demonstrates the low-level
 * TCP API independent of HTTP.
 *
 * For testing, you can use netcat on another machine:
 *   nc -l -p 9999
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

    io::print_str(L"\r\n=== Example: TCP Client ===\r\n\r\n");

    EFI_STATUS st = api::init_network();
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Network init failed.\r\n");
        return st;
    }

    // --- Resolve hostname ---
    io::print_str(L"[*] Resolving example.com...\r\n");
    UINT32 server_ip = 0;
    st = api::resolve_hostname("example.com", &server_ip);
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] DNS failed.\r\n");
        return st;
    }

    io::print_str(L"[+] Server IP: ");
    io::print_ip(server_ip);
    io::print_str(L"\r\n");

    // --- TCP connect to port 80 ---
    io::print_str(L"[*] Connecting to port 80...\r\n");
    st = api::tcp_connect(server_ip, 80);
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] TCP connect failed.\r\n");
        return st;
    }
    io::print_str(L"[+] Connected!\r\n");

    // --- Send a simple HTTP request ---
    const CHAR8* request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    UINTN req_len = utils::ascii_str_len(request);

    io::print_str(L"[*] Sending request (");
    io::print_dec(req_len);
    io::print_str(L" bytes)...\r\n");

    st = api::tcp_send(request, req_len);
    if (EFI_ERROR(st))
    {
        io::print_str(L"[!] Send failed.\r\n");
        api::tcp_close();
        return st;
    }

    // --- Receive response ---
    UINT8 buf[0x1000];
    memory::local_zero_mem(buf, sizeof(buf));
    UINTN rx_len = 0;

    io::print_str(L"[*] Waiting for response...\r\n");
    st = api::tcp_receive(buf, sizeof(buf) - 1, &rx_len, 5000);

    if (!EFI_ERROR(st) && rx_len > 0)
    {
        io::print_str(L"\r\n--- Response (");
        io::print_dec(rx_len);
        io::print_str(L" bytes) ---\r\n");
        io::print_ascii_n((CHAR8*)buf, rx_len);
        io::print_str(L"\r\n--- End ---\r\n");
    }
    else
    {
        io::print_str(L"[-] No response received.\r\n");
    }

    // --- Close connection ---
    api::tcp_close();
    io::print_str(L"\r\n[*] Connection closed. Done.\r\n");
    return EFI_SUCCESS;
}
