/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer storage interface.

Environment:

    Linux

--*/

#define _GNU_SOURCE
#include "platform_internal.h"
#ifdef CXPLAT_CLOG
#include "storage_linux.c.clog.h"
#endif

CXPLAT_STATUS
QuicStorageOpen(
    _In_opt_z_ const char * Path,
    _In_ CXPLAT_STORAGE_CHANGE_CALLBACK_HANDLER Callback,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_STORAGE** NewStorage
    )
{
    UNREFERENCED_PARAMETER(Path);
    UNREFERENCED_PARAMETER(Callback);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(NewStorage);
    // TODO
    return CXPLAT_STATUS_NOT_SUPPORTED;
}

void
QuicStorageClose(
    _In_opt_ CXPLAT_STORAGE* Storage
    )
{
    UNREFERENCED_PARAMETER(Storage);
    // TODO
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
QuicStorageReadValue(
    _In_ CXPLAT_STORAGE* Storage,
    _In_opt_z_ const char * Name,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength)
        uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength
    )
{
    UNREFERENCED_PARAMETER(Storage);
    UNREFERENCED_PARAMETER(Name);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    // TODO
    return CXPLAT_STATUS_NOT_SUPPORTED;
}
