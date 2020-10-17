/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the platform specific definitions for MsQuic structures
    and error codes.

Environment:

    Windows Kernel mode

--*/

#pragma once

#ifndef _MSCXPLAT_WINKERNEL_
#define _MSCXPLAT_WINKERNEL_

#include <ws2def.h>
#include <ws2ipdef.h>
#include <minwindef.h>
#include <ntstatus.h>
#include <basetsd.h>

typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;

typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#define UINT8_MAX   0xffui8
#define UINT16_MAX  0xffffui16
#define UINT32_MAX  0xffffffffui32
#define UINT64_MAX  0xffffffffffffffffui64

#ifndef STATUS_CXPLAT_HANDSHAKE_FAILURE
#define STATUS_CXPLAT_HANDSHAKE_FAILURE    ((NTSTATUS)0xC0240000L)
#endif

#ifndef STATUS_CXPLAT_VER_NEG_FAILURE
#define STATUS_CXPLAT_VER_NEG_FAILURE      ((NTSTATUS)0xC0240001L)
#endif

#ifndef STATUS_CXPLAT_USER_CANCELED
#define STATUS_CXPLAT_USER_CANCELED        ((NTSTATUS)0xC0240002L)
#endif

#ifndef STATUS_CXPLAT_INTERNAL_ERROR
#define STATUS_CXPLAT_INTERNAL_ERROR       ((NTSTATUS)0xC0240003L)
#endif

#ifndef STATUS_CXPLAT_PROTOCOL_VIOLATION
#define STATUS_CXPLAT_PROTOCOL_VIOLATION   ((NTSTATUS)0xC0240004L)
#endif

#ifndef STATUS_CXPLAT_CONNECTION_IDLE
#define STATUS_CXPLAT_CONNECTION_IDLE      ((NTSTATUS)0xC0240005L)
#endif

#ifndef STATUS_CXPLAT_CONNECTION_TIMEOUT
#define STATUS_CXPLAT_CONNECTION_TIMEOUT   ((NTSTATUS)0xC0240006L)
#endif

#ifndef STATUS_CXPLAT_ALPN_NEG_FAILURE
#define STATUS_CXPLAT_ALPN_NEG_FAILURE     ((NTSTATUS)0xC0240007L)
#endif

#define CXPLAT_API                        NTAPI
#define CXPLAT_STATUS                     NTSTATUS
#define CXPLAT_FAILED(X)                  (!NT_SUCCESS(X))
#define CXPLAT_SUCCEEDED(X)               NT_SUCCESS(X)

#define CXPLAT_STATUS_SUCCESS             STATUS_SUCCESS
#define CXPLAT_STATUS_PENDING             STATUS_PENDING
#define CXPLAT_STATUS_CONTINUE            STATUS_REPARSE
#define CXPLAT_STATUS_OUT_OF_MEMORY       STATUS_NO_MEMORY
#define CXPLAT_STATUS_INVALID_PARAMETER   STATUS_INVALID_PARAMETER
#define CXPLAT_STATUS_INVALID_STATE       STATUS_INVALID_DEVICE_STATE
#define CXPLAT_STATUS_NOT_SUPPORTED       STATUS_NOT_SUPPORTED
#define CXPLAT_STATUS_NOT_FOUND           STATUS_NOT_FOUND
#define CXPLAT_STATUS_BUFFER_TOO_SMALL    STATUS_BUFFER_TOO_SMALL
#define CXPLAT_STATUS_HANDSHAKE_FAILURE   STATUS_CXPLAT_HANDSHAKE_FAILURE
#define CXPLAT_STATUS_ABORTED             STATUS_CANCELLED
#define CXPLAT_STATUS_ADDRESS_IN_USE      STATUS_ADDRESS_ALREADY_EXISTS
#define CXPLAT_STATUS_CONNECTION_TIMEOUT  STATUS_CXPLAT_CONNECTION_TIMEOUT
#define CXPLAT_STATUS_CONNECTION_IDLE     STATUS_CXPLAT_CONNECTION_IDLE
#define CXPLAT_STATUS_UNREACHABLE         STATUS_HOST_UNREACHABLE
#define CXPLAT_STATUS_INTERNAL_ERROR      STATUS_CXPLAT_INTERNAL_ERROR
#define CXPLAT_STATUS_CONNECTION_REFUSED  STATUS_CONNECTION_REFUSED
#define CXPLAT_STATUS_PROTOCOL_ERROR      STATUS_CXPLAT_PROTOCOL_VIOLATION
#define CXPLAT_STATUS_VER_NEG_ERROR       STATUS_CXPLAT_VER_NEG_FAILURE
#define CXPLAT_STATUS_USER_CANCELED       STATUS_CXPLAT_USER_CANCELED
#define CXPLAT_STATUS_ALPN_NEG_FAILURE    STATUS_CXPLAT_ALPN_NEG_FAILURE

//
// Swaps byte orders between host and network endianness.
//
#ifdef RtlUshortByteSwap
#define QuicNetByteSwapShort(x) RtlUshortByteSwap(x)
#else
#define QuicNetByteSwapShort(x) ((uint16_t)((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8)))
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
QuicAddrIsValid(
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
QuicAddrCompareIp(
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
QuicAddrCompare(
    _In_ const CXPLAT_ADDR* const Addr1,
    _In_ const CXPLAT_ADDR* const Addr2
    )
{
    if (Addr1->si_family != Addr2->si_family ||
        Addr1->Ipv4.sin_port != Addr2->Ipv4.sin_port) {
        return FALSE;
    }
    return QuicAddrCompareIp(Addr1, Addr2);
}

inline
BOOLEAN
QuicAddrIsWildCard(
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
QuicAddrGetFamily(
    _In_ const CXPLAT_ADDR* const Addr
    )
{
    return (CXPLAT_ADDRESS_FAMILY)Addr->si_family;
}

inline
void
QuicAddrSetFamily(
    _Out_ CXPLAT_ADDR* Addr,
    _In_ CXPLAT_ADDRESS_FAMILY Family
    )
{
    Addr->si_family = (ADDRESS_FAMILY)Family;
}

inline
uint16_t // Returns in host byte order.
QuicAddrGetPort(
    _In_ const CXPLAT_ADDR* const Addr
    )
{
    return QuicNetByteSwapShort(Addr->Ipv4.sin_port);
}

inline
void
QuicAddrSetPort(
    _Inout_ CXPLAT_ADDR* Addr,
    _In_ uint16_t Port // Host byte order
    )
{
    Addr->Ipv4.sin_port = QuicNetByteSwapShort(Port);
}

inline
void
QuicAddrSetToLoopback(
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
QuicAddrIncrement(
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
QuicAddrHash(
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
QuicAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ CXPLAT_ADDR* Addr
    )
{
    Addr->Ipv4.sin_port = QuicNetByteSwapShort(Port);
    if (RtlIpv4StringToAddressExA(AddrStr, FALSE, &Addr->Ipv4.sin_addr, &Addr->Ipv4.sin_port) == STATUS_SUCCESS) {
        Addr->si_family = CXPLAT_ADDRESS_FAMILY_INET;
    } else if (RtlIpv6StringToAddressExA(AddrStr, &Addr->Ipv6.sin6_addr, &Addr->Ipv6.sin6_scope_id, &Addr->Ipv6.sin6_port) == STATUS_SUCCESS) {
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
QuicAddrToString(
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
    return Status == STATUS_SUCCESS;
}

#endif // _MSCXPLAT_WINKERNEL_
