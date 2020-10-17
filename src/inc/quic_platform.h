/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Platform definitions.

Supported Environments:

    Windows user mode
    Windows kernel mode
    Linux user mode

--*/

#pragma once

#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

//
// Time unit conversion.
//
#define NS_TO_US(x)     ((x) / 1000)
#define US_TO_NS(x)     ((x) * 1000)
#define NS100_TO_US(x)  ((x) / 10)
#define US_TO_NS100(x)  ((x) * 10)
#define MS_TO_NS100(x)  ((x)*10000)
#define NS100_TO_MS(x)  ((x)/10000)
#define US_TO_MS(x)     ((x) / 1000)
#define MS_TO_US(x)     ((x) * 1000)
#define US_TO_S(x)      ((x) / (1000 * 1000))
#define S_TO_US(x)      ((x) * 1000 * 1000)
#define S_TO_NS(x)      ((x) * 1000 * 1000 * 1000)
#define MS_TO_S(x)      ((x) / 1000)
#define S_TO_MS(x)      ((x) * 1000)

#define CXPLAT_CONTAINING_RECORD(address, type, field) \
    ((type *)((uint8_t*)(address) - offsetof(type, field)))

typedef struct CXPLAT_LIST_ENTRY {
    struct CXPLAT_LIST_ENTRY* Flink;
    struct CXPLAT_LIST_ENTRY* Blink;
} CXPLAT_LIST_ENTRY;

typedef struct CXPLAT_SINGLE_LIST_ENTRY {
    struct CXPLAT_SINGLE_LIST_ENTRY* Next;
} CXPLAT_SINGLE_LIST_ENTRY;

#ifndef FORCEINLINE
#if (_MSC_VER >= 1200)
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE __inline
#endif
#endif

//
// Different pool tags used for marking allocations.
//

#define CXPLAT_POOL_GENERIC   'CIUQ'  // QUIC - Generic QUIC
#define CXPLAT_POOL_CONN      'noCQ'  // QCon - QUIC connection
#define CXPLAT_POOL_TP        'PTCQ'  // QCTP - QUIC connection transport parameters
#define CXPLAT_POOL_STREAM    'mtSQ'  // QStm - QUIC stream
#define CXPLAT_POOL_SBUF      'fBSQ'  // QSBf - QUIC stream buffer
#define CXPLAT_POOL_META      'MFSQ'  // QSFM - QUIC sent frame metedata
#define CXPLAT_POOL_DATA      'atDQ'  // QDta - QUIC datagram buffer
#define CXPLAT_POOL_TEST      'tsTQ'  // QTst - QUIC test code
#define CXPLAT_POOL_PERF      'frPQ'  // QPrf - QUIC perf code
#define CXPLAT_POOL_TOOL      'loTQ'  // QTol - QUIC tool code

typedef enum CXPLAT_THREAD_FLAGS {
    CXPLAT_THREAD_FLAG_NONE               = 0x0000,
    CXPLAT_THREAD_FLAG_SET_IDEAL_PROC     = 0x0001,
    CXPLAT_THREAD_FLAG_SET_AFFINITIZE     = 0x0002,
    CXPLAT_THREAD_FLAG_HIGH_PRIORITY      = 0x0004
} CXPLAT_THREAD_FLAGS;

#ifdef DEFINE_ENUM_FLAG_OPERATORS
DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_THREAD_FLAGS);
#endif

#ifdef _KERNEL_MODE
#define CXPLAT_PLATFORM_TYPE 1
#include <quic_platform_winkernel.h>
#elif _WIN32
#define CXPLAT_PLATFORM_TYPE 2
#include <quic_platform_winuser.h>
#elif CXPLAT_PLATFORM_LINUX
#define CXPLAT_PLATFORM_TYPE 3
#include <quic_platform_linux.h>
#else
#define CXPLAT_PLATFORM_TYPE 0xFF
#error "Unsupported Platform"
#endif

#define QuicListEntryValidate(Entry) \
    CXPLAT_DBG_ASSERT( \
        (((Entry->Flink)->Blink) == Entry) && \
        (((Entry->Blink)->Flink) == Entry))

FORCEINLINE
void
QuicListInitializeHead(
    _Out_ CXPLAT_LIST_ENTRY* ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

_Must_inspect_result_
FORCEINLINE
BOOLEAN
QuicListIsEmpty(
    _In_ const CXPLAT_LIST_ENTRY* ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
void
QuicListInsertHead(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead,
    _Out_ __drv_aliasesMem CXPLAT_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    CXPLAT_LIST_ENTRY* Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
void
QuicListInsertTail(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    CXPLAT_LIST_ENTRY* Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE
CXPLAT_LIST_ENTRY*
QuicListRemoveHead(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead
    )
{
    QuicListEntryValidate(ListHead);
    CXPLAT_LIST_ENTRY* Entry = ListHead->Flink;
    CXPLAT_LIST_ENTRY* Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
BOOLEAN
QuicListEntryRemove(
    _In_ CXPLAT_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(Entry);
    CXPLAT_LIST_ENTRY* Flink = Entry->Flink;
    CXPLAT_LIST_ENTRY* Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

inline
void
QuicListMoveItems(
    _Inout_ CXPLAT_LIST_ENTRY* Source,
    _Inout_ CXPLAT_LIST_ENTRY* Destination
    )
{
    //
    // If there are items, copy them.
    //
    if (!QuicListIsEmpty(Source)) {

        if (QuicListIsEmpty(Destination)) {

            //
            // Copy the links of the Source.
            //
            Destination->Flink = Source->Flink;
            Destination->Blink = Source->Blink;

            //
            // Fix the item's links to point to new head.
            //
            Destination->Flink->Blink = Destination;
            Destination->Blink->Flink = Destination;

        } else {

            //
            // Fix Destination's current last item to point
            // to the first of Source.
            //
            Source->Flink->Blink = Destination->Blink;
            Destination->Blink->Flink = Source->Flink;

            //
            // Fix Destination's new last item to be the of Source's last item.
            //
            Source->Blink->Flink = Destination;
            Destination->Blink = Source->Blink;
        }

        //
        // Reset the Source to empty list.
        //
        QuicListInitializeHead(Source);
    }
}

FORCEINLINE
void
QuicListPushEntry(
    _Inout_ CXPLAT_SINGLE_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_SINGLE_LIST_ENTRY* Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

FORCEINLINE
CXPLAT_SINGLE_LIST_ENTRY*
QuicListPopEntry(
    _Inout_ CXPLAT_SINGLE_LIST_ENTRY* ListHead
    )
{
    CXPLAT_SINGLE_LIST_ENTRY* FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }
    return FirstEntry;
}

#include "quic_hashtable.h"
#include "quic_toeplitz.h"

//
// Test Interface for loading a self-signed certificate.
//

#ifdef CXPLAT_TEST_APIS

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_CREDENTIAL_CONFIG CXPLAT_CREDENTIAL_CONFIG;

typedef enum CXPLAT_SELF_SIGN_CERT_TYPE {
    CXPLAT_SELF_SIGN_CERT_USER,
    CXPLAT_SELF_SIGN_CERT_MACHINE
} CXPLAT_SELF_SIGN_CERT_TYPE;

_IRQL_requires_max_(PASSIVE_LEVEL)
const CXPLAT_CREDENTIAL_CONFIG*
QuicPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ const CXPLAT_CREDENTIAL_CONFIG* CredConfig
    );

#if defined(__cplusplus)
}
#endif

#endif // CXPLAT_TEST_APIS
