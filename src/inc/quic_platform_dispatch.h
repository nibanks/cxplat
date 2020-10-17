/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains function pointers and dispatch table for various
    datapath and platform functionalities.

Environment:

    Linux

--*/

#pragma once

#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE

#include "quic_platform.h"
#include "quic_datapath.h"

//
// Function pointers for PAL, DAL and TAL implementation.
//

typedef
void*
(*CXPLAT_ALLOC)(
    _In_ size_t ByteCount
    );

typedef
void
(*CXPLAT_FREE)(
    _Inout_ void* Mem
    );

typedef
void
(*CXPLAT_POOL_INITIALIZE)(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _Inout_ CXPLAT_POOL* Pool
    );

typedef
void
(*CXPLAT_POOL_UNINITIALIZE)(
    _Inout_ CXPLAT_POOL* Pool
    );

typedef
void*
(*CXPLAT_POOL_ALLOC)(
    _Inout_ CXPLAT_POOL* Pool
    );

typedef
void
(*CXPLAT_POOL_FREE)(
    _Inout_ CXPLAT_POOL* Pool,
    _In_ void* Entry
    );

typedef
void
(*CXPLAT_LOG)(
    _In_ CXPLAT_TRACE_LEVEL Level,
    _In_ const char* Fmt,
    _In_ va_list args
    );

typedef
CXPLAT_RECV_DATAGRAM*
(*CXPLAT_DATAPATH_RECVCONTEXT_TO_RECVBUFFER)(
    _In_ const CXPLAT_RECV_PACKET* const RecvPacket
    );

typedef
CXPLAT_RECV_PACKET*
(*CXPLAT_DATAPATH_RECVBUFFER_TO_RECVCONTEXT)(
    _In_ const CXPLAT_RECV_DATAGRAM* const RecvDatagram
    );

typedef
CXPLAT_STATUS
(*CXPLAT_DATAPATH_INITIALIZE)(
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ CXPLAT_DATAPATH* *NewDatapath
    );

typedef
void
(*CXPLAT_DATAPATH_UNINITIALIZE)(
    _In_ CXPLAT_DATAPATH* Datapath
    );

typedef
BOOLEAN
(*CXPLAT_DATAPATH_IS_PADDING_PREFERRED)(
    _In_ CXPLAT_DATAPATH* Datapath
    );

typedef
CXPLAT_STATUS
(*CXPLAT_DATAPATH_RESOLVE_ADDRESS)(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ CXPLAT_ADDR* Address
    );

typedef
CXPLAT_STATUS
(*CXPLAT_DATAPATH_BINDING_CREATE)(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const CXPLAT_ADDR* LocalAddress,
    _In_opt_ const CXPLAT_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_DATAPATH_BINDING** Binding
    );

typedef
void
(*CXPLAT_DATAPATH_BINDING_DELETE)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding
    );

typedef
uint16_t
(*CXPLAT_DATPATH_BINDING_GET_LOCAL_MTU)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding
    );

typedef
void
(*CXPLAT_DATAPATH_BINDING_GET_LOCAL_ADDRESS)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _Out_ CXPLAT_ADDR* Address
    );

typedef
void
(*CXPLAT_DATAPATH_BINDING_GET_REMOTE_ADDRESS)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _Out_ CXPLAT_ADDR* Address
    );

typedef
void
(*CXPLAT_DATAPATH_BINDING_RETURN_RECV_BUFFER)(
    _In_ CXPLAT_RECV_DATAGRAM* RecvPacketChain
    );

typedef
CXPLAT_DATAPATH_SEND_CONTEXT*
(*CXPLAT_DATAPATH_BINDING_ALLOC_SEND_CONTEXT)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    );

typedef
void
(*CXPLAT_DATAPATH_BINDING_FREE_SEND_CONTEXT)(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
CXPLAT_BUFFER*
(*CXPLAT_DATAPATH_BINDING_ALLOC_SEND_BUFFER)(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    );

typedef
void
(*CXPLAT_DATAPATH_BINDING_FREE_SEND_BUFFER)(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ CXPLAT_BUFFER* SendBuffer
    );

typedef
BOOLEAN
(*CXPLAT_DATAPATH_BINDING_IS_SEND_CONTEXT_FULL)(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
CXPLAT_STATUS
(*CXPLAT_DATAPATH_BINDING_SEND)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ const CXPLAT_ADDR* LocalAddress,
    _In_ const CXPLAT_ADDR* RemoteAddress,
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef
CXPLAT_STATUS
(*CXPLAT_DATAPATH_BINDING_SET_PARAM)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    );

typedef
CXPLAT_STATUS
(*CXPLAT_DATAPATH_BINDING_GET_PARAM)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    );

typedef
CXPLAT_STATUS
(*CXPLAT_RANDOM)(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );


typedef struct CXPLAT_PLATFORM_DISPATCH {
    CXPLAT_ALLOC Alloc;
    CXPLAT_FREE Free;
    CXPLAT_POOL_INITIALIZE PoolInitialize;
    CXPLAT_POOL_UNINITIALIZE PoolUninitialize;
    CXPLAT_POOL_ALLOC PoolAlloc;
    CXPLAT_POOL_FREE PoolFree;

    CXPLAT_LOG Log;

    CXPLAT_RANDOM Random;

    CXPLAT_DATAPATH_INITIALIZE DatapathInitialize;
    CXPLAT_DATAPATH_UNINITIALIZE DatapathUninitialize;
    CXPLAT_DATAPATH_RECVCONTEXT_TO_RECVBUFFER DatapathRecvContextToRecvPacket;
    CXPLAT_DATAPATH_RECVBUFFER_TO_RECVCONTEXT DatapathRecvPacketToRecvContext;
    CXPLAT_DATAPATH_IS_PADDING_PREFERRED DatapathIsPaddingPreferred;
    CXPLAT_DATAPATH_RESOLVE_ADDRESS DatapathResolveAddress;
    CXPLAT_DATAPATH_BINDING_CREATE DatapathBindingCreate;
    CXPLAT_DATAPATH_BINDING_DELETE DatapathBindingDelete;
    CXPLAT_DATPATH_BINDING_GET_LOCAL_MTU DatapathBindingGetLocalMtu;
    CXPLAT_DATAPATH_BINDING_GET_LOCAL_ADDRESS DatapathBindingGetLocalAddress;
    CXPLAT_DATAPATH_BINDING_GET_REMOTE_ADDRESS DatapathBindingGetRemoteAddress;
    CXPLAT_DATAPATH_BINDING_RETURN_RECV_BUFFER DatapathBindingReturnRecvPacket;
    CXPLAT_DATAPATH_BINDING_ALLOC_SEND_CONTEXT DatapathBindingAllocSendContext;
    CXPLAT_DATAPATH_BINDING_FREE_SEND_CONTEXT DatapathBindingFreeSendContext;
    CXPLAT_DATAPATH_BINDING_IS_SEND_CONTEXT_FULL DatapathBindingIsSendContextFull;
    CXPLAT_DATAPATH_BINDING_ALLOC_SEND_BUFFER DatapathBindingAllocSendBuffer;
    CXPLAT_DATAPATH_BINDING_FREE_SEND_BUFFER DatapathBindingFreeSendBuffer;
    CXPLAT_DATAPATH_BINDING_SEND DatapathBindingSend;
    CXPLAT_DATAPATH_BINDING_SET_PARAM DatapathBindingSetParam;
    CXPLAT_DATAPATH_BINDING_GET_PARAM DatapathBindingGetParam;

} CXPLAT_PLATFORM_DISPATCH;

extern CXPLAT_PLATFORM_DISPATCH* PlatDispatch;

#endif // CXPLAT_PLATFORM_DISPATCH_TABLE
