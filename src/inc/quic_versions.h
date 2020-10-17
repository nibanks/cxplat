/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC protocol versions.

--*/

#pragma once

//
// The QUIC version numbers, in network byte order.
//
#define CXPLAT_VERSION_VER_NEG    0x00000000U     // Version for 'Version Negotiation'
#define CXPLAT_VERSION_1          0x01000000U     // First official version
#define CXPLAT_VERSION_MS_1       0x0000cdabU     // First Microsoft version (currently same as latest draft)
#define CXPLAT_VERSION_DRAFT_27   0x1b0000ffU     // IETF draft 27
#define CXPLAT_VERSION_DRAFT_28   0x1c0000ffU     // IETF draft 28
#define CXPLAT_VERSION_DRAFT_29   0x1d0000ffU     // IETF draft 29
#define CXPLAT_VERSION_DRAFT_30   0x1e0000ffU     // IETF draft 30
#define CXPLAT_VERSION_DRAFT_31   0x1f0000ffU     // IETF draft 31

//
// The QUIC version numbers, in host byte order.
//
#define CXPLAT_VERSION_VER_NEG_H  0x00000000U     // Version for 'Version Negotiation'
#define CXPLAT_VERSION_1_H        0x00000001U     // First official version
#define CXPLAT_VERSION_1_MS_H     0xabcd0000U     // First Microsoft version (-1412628480 in decimal)
#define CXPLAT_VERSION_DRAFT_27_H 0xff00001bU     // IETF draft 27
#define CXPLAT_VERSION_DRAFT_28_H 0xff00001cU     // IETF draft 28
#define CXPLAT_VERSION_DRAFT_29_H 0xff00001dU     // IETF draft 29
#define CXPLAT_VERSION_DRAFT_30_H 0xff00001eU     // IETF draft 30
#define CXPLAT_VERSION_DRAFT_31_H 0xff00001fU     // IETF draft 31

//
// Represents a reserved version value; used to force version negotation.
//
#define CXPLAT_VERSION_RESERVED       0x0a0a0a0aU
#define CXPLAT_VERSION_RESERVED_MASK  0x0f0f0f0fU

//
// The latest QUIC version number.
//
#define CXPLAT_VERSION_LATEST     CXPLAT_VERSION_DRAFT_31
#define CXPLAT_VERSION_LATEST_H   CXPLAT_VERSION_DRAFT_31_H

inline
BOOLEAN
CxPlatIsVersionSupported(
    _In_ uint32_t Version // Network Byte Order
    )
{
    switch (Version) {
    case CXPLAT_VERSION_DRAFT_27:
    case CXPLAT_VERSION_DRAFT_28:
    case CXPLAT_VERSION_DRAFT_29:
    case CXPLAT_VERSION_DRAFT_30:
    case CXPLAT_VERSION_DRAFT_31:
    case CXPLAT_VERSION_MS_1:
        return TRUE;
    default:
        return FALSE;
    }
}

inline
BOOLEAN
CxPlatIsVersionReserved(
    _In_ uint32_t Version // Either Byte Order
    )
{
    return (Version & CXPLAT_VERSION_RESERVED_MASK) == CXPLAT_VERSION_RESERVED;
}
