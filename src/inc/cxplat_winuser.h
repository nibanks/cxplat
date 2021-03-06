/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the platform specific definitions for CxPlat structures
    and error codes.

Environment:

    Windows User mode

--*/

#pragma once

#ifndef _MSCXPLAT_WINUSER_
#define _MSCXPLAT_WINUSER_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdint.h>

#define SUCCESS_HRESULT_FROM_WIN32(x) \
    ((HRESULT)(((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16)))

#ifndef ERROR_CXPLAT_HANDSHAKE_FAILURE
#define ERROR_CXPLAT_HANDSHAKE_FAILURE    _HRESULT_TYPEDEF_(0x80410000L)
#endif

#ifndef ERROR_CXPLAT_VER_NEG_FAILURE
#define ERROR_CXPLAT_VER_NEG_FAILURE      _HRESULT_TYPEDEF_(0x80410001L)
#endif

#ifndef ERROR_CXPLAT_USER_CANCELED
#define ERROR_CXPLAT_USER_CANCELED        _HRESULT_TYPEDEF_(0x80410002L)
#endif

#ifndef ERROR_CXPLAT_INTERNAL_ERROR
#define ERROR_CXPLAT_INTERNAL_ERROR       _HRESULT_TYPEDEF_(0x80410003L)
#endif

#ifndef ERROR_CXPLAT_PROTOCOL_VIOLATION
#define ERROR_CXPLAT_PROTOCOL_VIOLATION   _HRESULT_TYPEDEF_(0x80410004L)
#endif

#ifndef ERROR_CXPLAT_CONNECTION_IDLE
#define ERROR_CXPLAT_CONNECTION_IDLE      _HRESULT_TYPEDEF_(0x80410005L)
#endif

#ifndef ERROR_CXPLAT_CONNECTION_TIMEOUT
#define ERROR_CXPLAT_CONNECTION_TIMEOUT   _HRESULT_TYPEDEF_(0x80410006L)
#endif

#ifndef ERROR_CXPLAT_ALPN_NEG_FAILURE
#define ERROR_CXPLAT_ALPN_NEG_FAILURE     _HRESULT_TYPEDEF_(0x80410007L)
#endif

#define CXPLAT_API                        __cdecl
#define CXPLAT_MAIN_EXPORT                __cdecl
#define CXPLAT_STATUS                     HRESULT
#define CXPLAT_FAILED(X)                  FAILED(X)
#define CXPLAT_SUCCEEDED(X)               SUCCEEDED(X)

#define CXPLAT_STATUS_SUCCESS             S_OK
#define CXPLAT_STATUS_PENDING             SUCCESS_HRESULT_FROM_WIN32(ERROR_IO_PENDING)
#define CXPLAT_STATUS_CONTINUE            SUCCESS_HRESULT_FROM_WIN32(ERROR_CONTINUE)
#define CXPLAT_STATUS_OUT_OF_MEMORY       E_OUTOFMEMORY
#define CXPLAT_STATUS_INVALID_PARAMETER   E_INVALIDARG
#define CXPLAT_STATUS_INVALID_STATE       E_NOT_VALID_STATE
#define CXPLAT_STATUS_NOT_SUPPORTED       E_NOINTERFACE
#define CXPLAT_STATUS_NOT_FOUND           HRESULT_FROM_WIN32(ERROR_NOT_FOUND)
#define CXPLAT_STATUS_BUFFER_TOO_SMALL    E_NOT_SUFFICIENT_BUFFER
#define CXPLAT_STATUS_HANDSHAKE_FAILURE   ERROR_CXPLAT_HANDSHAKE_FAILURE
#define CXPLAT_STATUS_ABORTED             E_ABORT
#define CXPLAT_STATUS_ADDRESS_IN_USE      HRESULT_FROM_WIN32(WSAEADDRINUSE)
#define CXPLAT_STATUS_CONNECTION_TIMEOUT  ERROR_CXPLAT_CONNECTION_TIMEOUT
#define CXPLAT_STATUS_CONNECTION_IDLE     ERROR_CXPLAT_CONNECTION_IDLE
#define CXPLAT_STATUS_UNREACHABLE         HRESULT_FROM_WIN32(ERROR_HOST_UNREACHABLE)
#define CXPLAT_STATUS_INTERNAL_ERROR      ERROR_CXPLAT_INTERNAL_ERROR
#define CXPLAT_STATUS_CONNECTION_REFUSED  HRESULT_FROM_WIN32(ERROR_CONNECTION_REFUSED)
#define CXPLAT_STATUS_PROTOCOL_ERROR      ERROR_CXPLAT_PROTOCOL_VIOLATION
#define CXPLAT_STATUS_VER_NEG_ERROR       ERROR_CXPLAT_VER_NEG_FAILURE
#define CXPLAT_STATUS_TLS_ERROR           HRESULT_FROM_WIN32(WSA_SECURE_HOST_NOT_FOUND)
#define CXPLAT_STATUS_USER_CANCELED       ERROR_CXPLAT_USER_CANCELED
#define CXPLAT_STATUS_ALPN_NEG_FAILURE    ERROR_CXPLAT_ALPN_NEG_FAILURE

//
// Swaps byte orders between host and network endianness.
//
#ifdef htons
#define CxPlatNetByteSwapShort(x) htons(x)
#else
#define CxPlatNetByteSwapShort(x) ((uint16_t)((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8)))
#endif

//
// IP Address Abstraction Helpers
//

typedef ADDRESS_FAMILY CXPLAT_ADDRESS_FAMILY;
typedef SOCKADDR_INET CXPLAT_ADDR;

#define CXPLAT_ADDR_V4_PORT_OFFSET        FIELD_OFFSET(SOCKADDR_IN, sin_port)
#define CXPLAT_ADDR_V4_IP_OFFSET          FIELD_OFFSET(SOCKADDR_IN, sin_addr)

#define CXPLAT_ADDR_V6_PORT_OFFSET        FIELD_OFFSET(SOCKADDR_IN6, sin6_port)
#define CXPLAT_ADDR_V6_IP_OFFSET          FIELD_OFFSET(SOCKADDR_IN6, sin6_addr)

#define CXPLAT_ADDRESS_FAMILY_UNSPEC AF_UNSPEC
#define CXPLAT_ADDRESS_FAMILY_INET AF_INET
#define CXPLAT_ADDRESS_FAMILY_INET6 AF_INET6

inline
BOOLEAN
CxPlatAddrIsValid(
    _In_ const CXPLAT_ADDR* const Addr
    )
{
    return
        Addr->si_family == CXPLAT_ADDRESS_FAMILY_UNSPEC ||
        Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET ||
        Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET6;
}

inline
BOOLEAN
CxPlatAddrCompareIp(
    _In_ const CXPLAT_ADDR* const Addr1,
    _In_ const CXPLAT_ADDR* const Addr2
    )
{
    if (Addr1->si_family == CXPLAT_ADDRESS_FAMILY_INET) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
BOOLEAN
CxPlatAddrCompare(
    _In_ const CXPLAT_ADDR* const Addr1,
    _In_ const CXPLAT_ADDR* const Addr2
    )
{
    if (Addr1->si_family != Addr2->si_family ||
        Addr1->Ipv4.sin_port != Addr2->Ipv4.sin_port) {
        return FALSE;
    }
    return CxPlatAddrCompareIp(Addr1, Addr2);
}

inline
BOOLEAN
CxPlatAddrIsWildCard(
    _In_ const CXPLAT_ADDR* const Addr
    )
{
    if (Addr->si_family == CXPLAT_ADDRESS_FAMILY_UNSPEC) {
        return TRUE;
    } else if (Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET) {
        const IN_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv4.sin_addr, &ZeroAddr, sizeof(IN_ADDR)) == 0;
    } else {
        const IN6_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv6.sin6_addr, &ZeroAddr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
CXPLAT_ADDRESS_FAMILY
CxPlatAddrGetFamily(
    _In_ const CXPLAT_ADDR* const Addr
    )
{
    return (CXPLAT_ADDRESS_FAMILY)Addr->si_family;
}

inline
void
CxPlatAddrSetFamily(
    _Inout_ CXPLAT_ADDR* Addr,
    _In_ CXPLAT_ADDRESS_FAMILY Family
    )
{
    Addr->si_family = (ADDRESS_FAMILY)Family;
}

inline
uint16_t // Returns in host byte order.
CxPlatAddrGetPort(
    _In_ const CXPLAT_ADDR* const Addr
    )
{
    return CxPlatNetByteSwapShort(Addr->Ipv4.sin_port);
}

inline
void
CxPlatAddrSetPort(
    _Out_ CXPLAT_ADDR* Addr,
    _In_ uint16_t Port // Host byte order
    )
{
    Addr->Ipv4.sin_port = CxPlatNetByteSwapShort(Port);
}

inline
void
CxPlatAddrSetToLoopback(
    _Inout_ CXPLAT_ADDR* Addr
    )
{
    if (Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET) {
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b1 = 127;
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4 = 1;
    } else {
        Addr->Ipv6.sin6_addr.u.Byte[15] = 1;
    }
}

//
// Test only API to increment the IP address value.
//
inline
void
CxPlatAddrIncrement(
    _Inout_ CXPLAT_ADDR* Addr
    )
{
    if (Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET) {
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4++;
    } else {
        Addr->Ipv6.sin6_addr.u.Byte[15]++;
    }
}

inline
uint32_t
CxPlatAddrHash(
    _In_ const CXPLAT_ADDR* Addr
    )
{
    uint32_t Hash = 5387; // A random prime number.
#define UPDATE_HASH(byte) Hash = ((Hash << 5) - Hash) + (byte)
    if (Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET) {
        UPDATE_HASH(Addr->Ipv4.sin_port & 0xFF);
        UPDATE_HASH(Addr->Ipv4.sin_port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv4.sin_addr); ++i) {
            UPDATE_HASH(((uint8_t*)&Addr->Ipv4.sin_addr)[i]);
        }
    } else {
        UPDATE_HASH(Addr->Ipv6.sin6_port & 0xFF);
        UPDATE_HASH(Addr->Ipv6.sin6_port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv6.sin6_addr); ++i) {
            UPDATE_HASH(((uint8_t*)&Addr->Ipv6.sin6_addr)[i]);
        }
    }
    return Hash;
}

#define CXPLAT_LOCALHOST_FOR_AF(Af) "localhost"

inline
BOOLEAN
CxPlatAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ CXPLAT_ADDR* Addr
    )
{
    Addr->Ipv4.sin_port = CxPlatNetByteSwapShort(Port);
    if (RtlIpv4StringToAddressExA(AddrStr, FALSE, &Addr->Ipv4.sin_addr, &Addr->Ipv4.sin_port) == NO_ERROR) {
        Addr->si_family = CXPLAT_ADDRESS_FAMILY_INET;
    } else if (RtlIpv6StringToAddressExA(AddrStr, &Addr->Ipv6.sin6_addr, &Addr->Ipv6.sin6_scope_id, &Addr->Ipv6.sin6_port) == NO_ERROR) {
        Addr->si_family = CXPLAT_ADDRESS_FAMILY_INET6;
    } else {
        return FALSE;
    }
    return TRUE;
}

//
// Represents an IP address and (optionally) port number as a string.
//
typedef struct CXPLAT_ADDR_STR {
    char Address[64];
} CXPLAT_ADDR_STR;

inline
BOOLEAN
CxPlatAddrToString(
    _In_ const CXPLAT_ADDR* Addr,
    _Out_ CXPLAT_ADDR_STR* AddrStr
    )
{
    LONG Status;
    ULONG AddrStrLen = ARRAYSIZE(AddrStr->Address);
    if (Addr->si_family == CXPLAT_ADDRESS_FAMILY_INET) {
        Status =
            RtlIpv4AddressToStringExA(
                &Addr->Ipv4.sin_addr,
                Addr->Ipv4.sin_port,
                AddrStr->Address,
                &AddrStrLen);
    } else {
        Status =
            RtlIpv6AddressToStringExA(
                &Addr->Ipv6.sin6_addr,
                0,
                Addr->Ipv6.sin6_port,
                AddrStr->Address,
                &AddrStrLen);
    }
    return Status == NO_ERROR;
}

#endif // _MSCXPLAT_WINUSER_
