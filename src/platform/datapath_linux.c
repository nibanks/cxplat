/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#define _GNU_SOURCE
#include "platform_internal.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <inttypes.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include "quic_platform_dispatch.h"
#ifdef CXPLAT_CLOG
#include "datapath_linux.c.clog.h"
#endif

CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(CXPLAT_BUFFER, Length) <= sizeof(size_t)), "(sizeof(CXPLAT_BUFFER.Length) == sizeof(size_t) must be TRUE.");
CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(CXPLAT_BUFFER, Buffer) == sizeof(void*)), "(sizeof(CXPLAT_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

//
// TODO: Support batching.
//
#define CXPLAT_MAX_BATCH_SEND 1

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct CXPLAT_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    CXPLAT_POOL* OwningPool;

    //
    // The recv buffer used by CxPlat.
    //
    CXPLAT_RECV_DATAGRAM RecvPacket;

    //
    // Represents the address (source and destination) information of the
    // packet.
    //
    CXPLAT_TUPLE Tuple;

    //
    // Buffer that actually stores the UDP payload.
    //
    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // This follows the recv block.
    //
    // CXPLAT_RECV_PACKET RecvContext;

} CXPLAT_DATAPATH_RECV_BLOCK;

//
// Send context.
//

typedef struct CXPLAT_DATAPATH_SEND_CONTEXT {
    //
    // Indicates if the send should be bound to a local address.
    //
    BOOLEAN Bind;

    //
    // The local address to bind to.
    //
    CXPLAT_ADDR LocalAddress;

    //
    // The remote address to send to.
    //
    CXPLAT_ADDR RemoteAddress;

    //
    // Linkage to pending send list.
    //
    CXPLAT_LIST_ENTRY PendingSendLinkage;

    //
    // Indicates if the send is pending.
    //
    BOOLEAN Pending;

    //
    // The type of ECN markings needed for send.
    //
    CXPLAT_ECN_TYPE ECN;

    //
    // The proc context owning this send context.
    //
    struct CXPLAT_DATAPATH_PROC_CONTEXT *Owner;

    //
    // BufferCount - The buffer count in use.
    //
    // CurrentIndex - The current index of the Buffers to be sent.
    //
    // Buffers - Send buffers.
    //
    // Iovs - IO vectors used for doing sends on the socket.
    //
    // TODO: Better way to reconcile layout difference
    // between CXPLAT_BUFFER and struct iovec?
    //
    size_t BufferCount;
    size_t CurrentIndex;
    CXPLAT_BUFFER Buffers[CXPLAT_MAX_BATCH_SEND];
    struct iovec Iovs[CXPLAT_MAX_BATCH_SEND];

} CXPLAT_DATAPATH_SEND_CONTEXT;

//
// Socket context.
//
typedef struct CXPLAT_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    CXPLAT_DATAPATH_BINDING* Binding;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // The cleanup event FD used by this socket context.
    //
    int CleanupFd;

    //
    // Used to register different event FD with epoll.
    //
#define CXPLAT_SOCK_EVENT_CLEANUP 0
#define CXPLAT_SOCK_EVENT_SOCKET  1
    uint8_t EventContexts[2];

    //
    // Indicates if sends are waiting for the socket to be write ready.
    //
    BOOLEAN SendWaiting;

    //
    // The I/O vector for receive datagrams.
    //
    struct iovec RecvIov;

    //
    // The control buffer used in RecvMsgHdr.
    //
    char RecvMsgControl[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                        CMSG_SPACE(sizeof(struct in_pktinfo)) +
                        2 * CMSG_SPACE(sizeof(int))];

    //
    // The buffer used to receive msg headers on socket.
    //
    struct msghdr RecvMsgHdr;

    //
    // The receive block currently being used for receives on this socket.
    //
    CXPLAT_DATAPATH_RECV_BLOCK* CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //
    CXPLAT_LIST_ENTRY PendingSendContextHead;

} CXPLAT_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct CXPLAT_DATAPATH_BINDING {

    //
    // A pointer to datapath object.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The client context for this binding.
    //
    void *ClientContext;

    //
    // The local address for the binding.
    //
    CXPLAT_ADDR LocalAddress;

    //
    //  The remote address for the binding.
    //
    CXPLAT_ADDR RemoteAddress;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_RUNDOWN_REF Rundown;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Indicates the binding is shut down.
    //
    BOOLEAN Shutdown : 1;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Set of socket contexts one per proc.
    //
    CXPLAT_SOCKET_CONTEXT SocketContexts[];

} CXPLAT_DATAPATH_BINDING;

//
// A per processor datapath context.
//
typedef struct CXPLAT_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The Epoll FD for this proc context.
    //
    int EpollFd;

    //
    // The event FD for this proc context.
    //
    int EventFd;

    //
    // The index of the context in the datapath's array.
    //
    uint32_t Index;

    //
    // The epoll wait thread.
    //
    CXPLAT_THREAD EpollWaitThread;

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvBlockPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendBufferPool;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendContextPool;

} CXPLAT_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {
    //
    // If datapath is shutting down.
    //
    BOOLEAN volatile Shutdown;

    //
    // The max send batch size.
    // TODO: See how send batching can be enabled.
    //
    uint8_t MaxSendBatchSize;

    //
    // A reference rundown on the datapath binding.
    //
    CXPLAT_RUNDOWN_REF BindingsRundown;

    //
    // The CxPlat receive handler.
    //
    CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvHandler;

    //
    // The CxPlat unreachable handler.
    //
    CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachHandler;

    //
    // The length of recv context used by CxPlat.
    //
    size_t ClientRecvContextLength;

    //
    // The proc count to create per proc datapath state.
    //
    uint32_t ProcCount;

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT ProcContexts[];

} CXPLAT_DATAPATH;

void*
CxPlatDataPathWorkerThread(
    _In_ void* Context
    );

CXPLAT_STATUS
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t Index,
    _Out_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    int EpollFd = INVALID_SOCKET_FD;
    int EventFd = INVALID_SOCKET_FD;
    int Ret = 0;
    uint32_t RecvPacketLength = 0;
    BOOLEAN EventFdAdded = FALSE;

    CXPLAT_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(CXPLAT_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    ProcContext->Index = Index;
    CxPlatPoolInitialize(
        TRUE,
        RecvPacketLength,
        CXPLAT_POOL_DATA,
        &ProcContext->RecvBlockPool);
    CxPlatPoolInitialize(
        TRUE,
        MAX_UDP_PAYLOAD_LENGTH,
        CXPLAT_POOL_DATA,
        &ProcContext->SendBufferPool);
    CxPlatPoolInitialize(
        TRUE,
        sizeof(CXPLAT_DATAPATH_SEND_CONTEXT),
        CXPLAT_POOL_GENERIC,
        &ProcContext->SendContextPool);

    EpollFd = epoll_create1(EPOLL_CLOEXEC);
    if (EpollFd == INVALID_SOCKET_FD) {
        Status = errno;
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "epoll_create1(EPOLL_CLOEXEC) failed");
        goto Exit;
    }

    EventFd = eventfd(0, EFD_CLOEXEC);
    if (EventFd == INVALID_SOCKET_FD) {
        Status = errno;
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "eventfd failed");
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = NULL
        }
    };

    Ret = epoll_ctl(EpollFd, EPOLL_CTL_ADD, EventFd, &EvtFdEpEvt);
    if (Ret != 0) {
        Status = errno;
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "epoll_ctl(EPOLL_CTL_ADD) failed");
        goto Exit;
    }

    EventFdAdded = TRUE;

    ProcContext->Datapath = Datapath;
    ProcContext->EpollFd = EpollFd;
    ProcContext->EventFd = EventFd;

    //
    // Starting the thread must be done after the rest of the ProcContext
    // members have been initialized. Because the thread start routine accesses
    // ProcContext members.
    //

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        0,
        0,
        NULL,
        CxPlatDataPathWorkerThread,
        ProcContext
    };

    Status = CxPlatThreadCreate(&ThreadConfig, &ProcContext->EpollWaitThread);
    if (CXPLAT_FAILED(Status)) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate failed");
        goto Exit;
    }

Exit:

    if (CXPLAT_FAILED(Status)) {
        if (EventFdAdded) {
            epoll_ctl(EpollFd, EPOLL_CTL_DEL, EventFd, NULL);
        }
        if (EventFd != INVALID_SOCKET_FD) {
            close(EventFd);
        }
        if (EpollFd != INVALID_SOCKET_FD) {
            close(EpollFd);
        }
        CxPlatPoolUninitialize(&ProcContext->RecvBlockPool);
        CxPlatPoolUninitialize(&ProcContext->SendBufferPool);
        CxPlatPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}

void
CxPlatProcessorContextUninitialize(
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    const eventfd_t Value = 1;
    eventfd_write(ProcContext->EventFd, Value);
    CxPlatThreadWait(&ProcContext->EpollWaitThread);
    CxPlatThreadDelete(&ProcContext->EpollWaitThread);

    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, ProcContext->EventFd, NULL);
    close(ProcContext->EventFd);
    close(ProcContext->EpollFd);

    CxPlatPoolUninitialize(&ProcContext->RecvBlockPool);
    CxPlatPoolUninitialize(&ProcContext->SendBufferPool);
    CxPlatPoolUninitialize(&ProcContext->SendContextPool);
}

CXPLAT_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ CXPLAT_DATAPATH* *NewDataPath
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathInitialize(
            ClientRecvContextLength,
            RecvCallback,
            UnreachableCallback,
            NewDataPath);
#else
    if (RecvCallback == NULL ||
        UnreachableCallback == NULL ||
        NewDataPath == NULL) {
        return CXPLAT_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;

    size_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
            CxPlatProcMaxCount() * sizeof(CXPLAT_DATAPATH_PROC_CONTEXT);

    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength);
    if (Datapath == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(Datapath, DatapathLength);
    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = CxPlatProcMaxCount();
    Datapath->MaxSendBatchSize = CXPLAT_MAX_BATCH_SEND;
    CxPlatRundownInitialize(&Datapath->BindingsRundown);

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        Status = CxPlatProcessorContextInitialize(Datapath, i, &Datapath->ProcContexts[i]);
        if (CXPLAT_FAILED(Status)) {
            Datapath->Shutdown = TRUE;
            for (uint32_t j = 0; j < i; j++) {
                CxPlatProcessorContextUninitialize(&Datapath->ProcContexts[j]);
            }
            goto Exit;
        }
    }

    *NewDataPath = Datapath;
    Datapath = NULL;

Exit:

    if (Datapath != NULL) {
        CxPlatRundownUninitialize(&Datapath->BindingsRundown);
        CXPLAT_FREE(Datapath);
    }

    return Status;
#endif
}

void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathUninitialize(Datapath);
#else
    CxPlatRundownReleaseAndWait(&Datapath->BindingsRundown);

    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatProcessorContextUninitialize(&Datapath->ProcContexts[i]);
    }

    CxPlatRundownUninitialize(&Datapath->BindingsRundown);
    CXPLAT_FREE(Datapath);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return 0;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathIsPaddingPreferred(Datapath);
#else
    UNREFERENCED_PARAMETER(Datapath);
    //
    // The windows implementation returns TRUE only if GSO is supported and
    // this DAL implementation doesn't support GSO currently.
    //
    return FALSE;
#endif
}

CXPLAT_DATAPATH_RECV_BLOCK*
CxPlatDataPathAllocRecvBlock(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ProcIndex
    )
{
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        CxPlatPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvBlockPool);
    if (RecvBlock == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH_RECV_BLOCK",
            0);
    } else {
        CxPlatZeroMemory(RecvBlock, sizeof(*RecvBlock));
        RecvBlock->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvBlockPool;
        RecvBlock->RecvPacket.Buffer = RecvBlock->Buffer;
        RecvBlock->RecvPacket.Allocated = TRUE;
    }
    return RecvBlock;
}

void
CxPlatDataPathPopulateTargetAddress(
    _In_ CXPLAT_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ CXPLAT_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    CxPlatZeroMemory(Address, sizeof(CXPLAT_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //

        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;

        if (Family == CXPLAT_ADDRESS_FAMILY_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //

            SockAddrIn->sin_family = CXPLAT_ADDRESS_FAMILY_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        } else {
            Address->Ipv6 = *SockAddrIn6;
            return;
        }
    } else if (AddrInfo->ai_addr->sa_family == AF_INET) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        CXPLAT_FRE_ASSERT(FALSE);
    }
}

CXPLAT_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ CXPLAT_ADDR* Address
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathResolveAddress(Datapath, HostName, Address);
#else
    UNREFERENCED_PARAMETER(Datapath);
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    CxPlatTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
    CxPlatTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = CXPLAT_STATUS_DNS_RESOLUTION_ERROR;

Exit:

    return Status;
#endif
}

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//

CXPLAT_STATUS
CxPlatSocketContextInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ const CXPLAT_ADDR* LocalAddress,
    _In_ const CXPLAT_ADDR* RemoteAddress
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    CXPLAT_ADDR MappedAddress = {0};
    socklen_t AssignedLocalAddressLength = 0;

    CXPLAT_DATAPATH_BINDING* Binding = SocketContext->Binding;

    for (uint32_t i = 0; i < ARRAYSIZE(SocketContext->EventContexts); ++i) {
        SocketContext->EventContexts[i] = i;
    }

    SocketContext->CleanupFd = eventfd(0, EFD_CLOEXEC);
    if (SocketContext->CleanupFd == INVALID_SOCKET_FD) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "eventfd failed");
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = &SocketContext->EventContexts[CXPLAT_SOCK_EVENT_CLEANUP]
        }
    };

    if (epoll_ctl(
            ProcContext->EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->CleanupFd,
            &EvtFdEpEvt) != 0) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "epoll_ctl(EPOLL_CTL_ADD) failed");
        goto Exit;
    }

    //
    // Create datagram socket.
    //
    SocketContext->SocketFd =
        socket(
            AF_INET6,
            SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, // TODO check if SOCK_CLOEXEC is required?
            IPPROTO_UDP);
    if (SocketContext->SocketFd == INVALID_SOCKET_FD) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }

    //
    // Set dual (IPv4 & IPv6) socket mode.
    //
    Option = FALSE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_V6ONLY) failed");
        goto Exit;
    }

    //
    // Set DON'T FRAG socket option.
    //

    //
    // Windows: setsockopt IPPROTO_IP IP_DONTFRAGMENT TRUE.
    // Linux: IP_DONTFRAGMENT option is not available. IPV6_MTU_DISCOVER is the
    // apparent alternative.
    // TODO: Verify this.
    //
    Option = IP_PMTUDISC_DO;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_MTU_DISCOVER) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_DONTFRAG,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_DONTFRAG) failed");
        goto Exit;
    }

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //

    //
    // Windows: setsockopt IPPROTO_IPV6 IPV6_PKTINFO TRUE.
    // Android: Returns EINVAL. IPV6_PKTINFO option is not present in documentation.
    // IPV6_RECVPKTINFO seems like is the alternative.
    // TODO: Check if this works as expected?
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVPKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVPKTINFO) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_PKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_PKTINFO) failed");
        goto Exit;
    }

    //
    // Set socket option to receive TOS (= DSCP + ECN) information from the
    // incoming packet.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVTCLASS,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVTCLASS) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_RECVTOS,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_RECVTOS) failed");
        goto Exit;
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //
    Option = INT32_MAX;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_RCVBUF,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_RCVBUF) failed");
        goto Exit;
    }

    //
    // The port is shared across processors.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_REUSEADDR) failed");
        goto Exit;
    }

    CxPlatCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
    if (MappedAddress.Ipv6.sin6_family == CXPLAT_ADDRESS_FAMILY_INET6) {
        MappedAddress.Ipv6.sin6_family = AF_INET6;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            &MappedAddress.Ip,
            sizeof(MappedAddress));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "bind failed");
        goto Exit;
    }

    if (RemoteAddress != NULL) {
        CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
        CxPlatConvertToMappedV6(RemoteAddress, &MappedAddress);

        if (MappedAddress.Ipv6.sin6_family == CXPLAT_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }

        Result =
            connect(
                SocketContext->SocketFd,
                &MappedAddress.Ip,
                sizeof(MappedAddress));

        if (Result == SOCKET_ERROR) {
            Status = errno;
            CxPlatTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "connect failed");
            goto Exit;
        }
    }


    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
    Result =
        getsockname(
            SocketContext->SocketFd,
            (struct sockaddr *)&Binding->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
        Binding->LocalAddress.Ipv6.sin6_family = CXPLAT_ADDRESS_FAMILY_INET6;
    }

Exit:

    if (CXPLAT_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

    const eventfd_t Value = 1;
    eventfd_write(SocketContext->CleanupFd, Value);
}

void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    if (SocketContext->CurrentRecvBlock != NULL) {
        CxPlatDataPathBindingReturnRecvDatagrams(&SocketContext->CurrentRecvBlock->RecvPacket);
    }

    while (!CxPlatListIsEmpty(&SocketContext->PendingSendContextHead)) {
        CxPlatDataPathBindingFreeSendContext(
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&SocketContext->PendingSendContextHead),
                CXPLAT_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage));
    }

    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
    epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->CleanupFd, NULL);
    close(SocketContext->CleanupFd);
    close(SocketContext->SocketFd);

    CxPlatRundownRelease(&SocketContext->Binding->Rundown);
}

CXPLAT_STATUS
CxPlatSocketContextPrepareReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            CxPlatDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                CxPlatProcCurrentNumber());
        if (SocketContext->CurrentRecvBlock == NULL) {
            CxPlatTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_DATAPATH_RECV_BLOCK",
                0);
            return CXPLAT_STATUS_OUT_OF_MEMORY;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.BufferLength = SocketContext->RecvIov.iov_len;
    SocketContext->CurrentRecvBlock->RecvPacket.Tuple = (CXPLAT_TUPLE*)&SocketContext->CurrentRecvBlock->Tuple;

    CxPlatZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    CxPlatZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress);
    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;
    SocketContext->RecvMsgHdr.msg_control = SocketContext->RecvMsgControl;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControl);
    SocketContext->RecvMsgHdr.msg_flags = 0;

    return CXPLAT_STATUS_SUCCESS;
}

CXPLAT_STATUS
CxPlatSocketContextStartReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ int EpollFd
    )
{
    CXPLAT_STATUS Status = CxPlatSocketContextPrepareReceive(SocketContext);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    struct epoll_event SockFdEpEvt = {
        .events = EPOLLIN | EPOLLET,
        .data = {
            .ptr = &SocketContext->EventContexts[CXPLAT_SOCK_EVENT_SOCKET]
        }
    };

    int Ret =
        epoll_ctl(
            EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->SocketFd,
            &SockFdEpEvt);
    if (Ret != 0) {
        Status = Ret;
        CxPlatTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "epoll_ctl failed");
        goto Error;
    }

Error:

    if (CXPLAT_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ ssize_t BytesTransferred
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;

    CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);
    CXPLAT_RECV_DATAGRAM* RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;

    BOOLEAN FoundLocalAddr = FALSE;
    BOOLEAN FoundTOS = FALSE;
    CXPLAT_ADDR* LocalAddr = &RecvPacket->Tuple->LocalAddress;
    if (LocalAddr->Ipv6.sin6_family == AF_INET6) {
        LocalAddr->Ipv6.sin6_family = CXPLAT_ADDRESS_FAMILY_INET6;
    }
    CXPLAT_ADDR* RemoteAddr = &RecvPacket->Tuple->RemoteAddress;
    if (RemoteAddr->Ipv6.sin6_family == AF_INET6) {
        RemoteAddr->Ipv6.sin6_family = CXPLAT_ADDRESS_FAMILY_INET6;
    }
    CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

    RecvPacket->TypeOfService = 0;

    struct cmsghdr *CMsg;
    for (CMsg = CMSG_FIRSTHDR(&SocketContext->RecvMsgHdr);
         CMsg != NULL;
         CMsg = CMSG_NXTHDR(&SocketContext->RecvMsgHdr, CMsg)) {

        if (CMsg->cmsg_level == IPPROTO_IPV6) {
            if (CMsg->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
                LocalAddr->Ip.sa_family = CXPLAT_ADDRESS_FAMILY_INET6;
                LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                CxPlatConvertFromMappedV6(LocalAddr, LocalAddr);

                LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                FoundLocalAddr = TRUE;
            } else if (CMsg->cmsg_type == IPV6_TCLASS) {
                RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                FoundTOS = TRUE;
            }
        } else if (CMsg->cmsg_level == IPPROTO_IP) {
            if (CMsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
                LocalAddr->Ip.sa_family = CXPLAT_ADDRESS_FAMILY_INET;
                LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
                LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                FoundLocalAddr = TRUE;
            } else if (CMsg->cmsg_type == IP_TOS) {
                RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                FoundTOS = TRUE;
            }
        }
    }

    CXPLAT_FRE_ASSERT(FoundLocalAddr);
    CXPLAT_FRE_ASSERT(FoundTOS);

    CxPlatTraceEvent(
        DatapathRecv,
        "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
        SocketContext->Binding,
        (uint32_t)BytesTransferred,
        (uint32_t)BytesTransferred,
        CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

    CXPLAT_DBG_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    RecvPacket->PartitionIndex = ProcContext->Index;

    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath->RecvHandler);
    SocketContext->Binding->Datapath->RecvHandler(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RecvPacket);

    Status = CxPlatSocketContextPrepareReceive(SocketContext);

    //
    // Prepare can only fail under low memory condition. Treat it as a fatal
    // error.
    //
    CXPLAT_FRE_ASSERT(CXPLAT_SUCCEEDED(Status));
}

CXPLAT_STATUS
CxPlatSocketContextPendSend(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_opt_ const CXPLAT_ADDR* LocalAddress,
    _In_ const CXPLAT_ADDR* RemoteAddress
    )
{
    if (!SocketContext->SendWaiting) {

        struct epoll_event SockFdEpEvt = {
            .events = EPOLLIN | EPOLLOUT | EPOLLET,
            .data = {
                .ptr = &SocketContext->EventContexts[CXPLAT_SOCK_EVENT_SOCKET]
            }
        };

        int Ret =
            epoll_ctl(
                ProcContext->EpollFd,
                EPOLL_CTL_MOD,
                SocketContext->SocketFd,
                &SockFdEpEvt);
        if (Ret != 0) {
            CxPlatTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                errno,
                "epoll_ctl failed");
            return errno;
        }

        if (LocalAddress != NULL) {
            CxPlatCopyMemory(
                &SendContext->LocalAddress,
                LocalAddress,
                sizeof(*LocalAddress));
            SendContext->Bind = TRUE;
        }

        CxPlatCopyMemory(
            &SendContext->RemoteAddress,
            RemoteAddress,
            sizeof(*RemoteAddress));

        SocketContext->SendWaiting = TRUE;
    }

    if (SendContext->Pending) {
        //
        // This was a send that was already pending, so we need to add it back
        // to the head of the queue.
        //
        CxPlatListInsertHead(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
    } else {
        //
        // This is a new send that wasn't previously pended. Add it to the end
        // of the queue.
        //
        CxPlatListInsertTail(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
        SendContext->Pending = TRUE;
    }

    return CXPLAT_STATUS_SUCCESS;
}

CXPLAT_STATUS
CxPlatSocketContextSendComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;

    if (SocketContext->SendWaiting) {

        struct epoll_event SockFdEpEvt = {
            .events = EPOLLIN | EPOLLET,
            .data = {
                .ptr = &SocketContext->EventContexts[CXPLAT_SOCK_EVENT_SOCKET]
            }
        };

        int Ret =
            epoll_ctl(
                ProcContext->EpollFd,
                EPOLL_CTL_MOD,
                SocketContext->SocketFd,
                &SockFdEpEvt);
        if (Ret != 0) {
            Status = Ret;
            CxPlatTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                Status,
                "epoll_ctl failed");
            goto Exit;
        }

        SocketContext->SendWaiting = FALSE;
    }

    while (!CxPlatListIsEmpty(&SocketContext->PendingSendContextHead)) {
        CXPLAT_DATAPATH_SEND_CONTEXT* SendContext =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&SocketContext->PendingSendContextHead),
                CXPLAT_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage);

        Status =
            CxPlatDataPathBindingSend(
                SocketContext->Binding,
                SendContext->Bind ? &SendContext->LocalAddress : NULL,
                &SendContext->RemoteAddress,
                SendContext);
        if (CXPLAT_FAILED(Status)) {
            goto Exit;
        }

        if (SocketContext->SendWaiting) {
            break;
        }
    }

Exit:

    return Status;
}

void
CxPlatSocketContextProcessEvents(
    _In_ void* EventPtr,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ int Events
    )
{
    uint8_t EventType = *(uint8_t*)EventPtr;
    CXPLAT_SOCKET_CONTEXT* SocketContext =
        (CXPLAT_SOCKET_CONTEXT*)(
            (uint8_t*)CXPLAT_CONTAINING_RECORD(EventPtr, CXPLAT_SOCKET_CONTEXT, EventContexts) -
            EventType);

    if (EventType == CXPLAT_SOCK_EVENT_CLEANUP) {
        CXPLAT_DBG_ASSERT(SocketContext->Binding->Shutdown);
        CxPlatSocketContextUninitializeComplete(SocketContext, ProcContext);
        return;
    }

    CXPLAT_DBG_ASSERT(EventType == CXPLAT_SOCK_EVENT_SOCKET);

    if (EPOLLERR & Events) {
        int ErrNum = 0;
        socklen_t OptLen = sizeof(ErrNum);
        ssize_t Ret =
            getsockopt(
                SocketContext->SocketFd,
                SOL_SOCKET,
                SO_ERROR,
                &ErrNum,
                &OptLen);
        if (Ret < 0) {
            CxPlatTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                errno,
                "getsockopt(SO_ERROR) failed");
        } else {
            CxPlatTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                ErrNum,
                "Socket error event");

            //
            // Send unreachable notification to CxPlat if any related
            // errors were received.
            //
            if (ErrNum == ECONNREFUSED ||
                ErrNum == EHOSTUNREACH ||
                ErrNum == ENETUNREACH) {
                SocketContext->Binding->Datapath->UnreachHandler(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    &SocketContext->Binding->RemoteAddress);
            }
        }
    }

    if (EPOLLIN & Events) {
        while (TRUE) {
            CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);

            ssize_t Ret =
                recvmsg(
                    SocketContext->SocketFd,
                    &SocketContext->RecvMsgHdr,
                    0);
            if (Ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    CxPlatTraceEvent(
                        DatapathErrorStatus,
                        "[ udp][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "recvmsg failed");
                }
                break;
            } else {
                CxPlatSocketContextRecvComplete(SocketContext, ProcContext, Ret);
            }
        }
    }

    if (EPOLLOUT & Events) {
        CxPlatSocketContextSendComplete(SocketContext, ProcContext);
    }
}

//
// Datapath binding interface.
//

CXPLAT_STATUS
CxPlatDataPathBindingCreate(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const CXPLAT_ADDR* LocalAddress,
    _In_opt_ const CXPLAT_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_DATAPATH_BINDING** NewBinding
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingCreate(
            Datapath,
            LocalAddress,
            RemoteAddress,
            RecvCallbackContext,
            NewBinding);
#else
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;

    uint32_t SocketCount = Datapath->ProcCount; // TODO - Only use 1 for client (RemoteAddress != NULL) bindings?
    size_t BindingLength =
        sizeof(CXPLAT_DATAPATH_BINDING) +
        SocketCount * sizeof(CXPLAT_SOCKET_CONTEXT);

    CXPLAT_DATAPATH_BINDING* Binding =
        (CXPLAT_DATAPATH_BINDING*)CXPLAT_ALLOC_PAGED(BindingLength);
    if (Binding == NULL) {
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH_BINDING",
            BindingLength);
        goto Exit;
    }

    CxPlatTraceLogInfo(
        DatapathCreate,
        "[ udp][%p] Created.",
        Binding);

    CxPlatZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->Mtu = CXPLAT_MAX_MTU;
    CxPlatRundownInitialize(&Binding->Rundown);
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = CXPLAT_ADDRESS_FAMILY_INET6;
    }
    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET_FD;
        Binding->SocketContexts[i].RecvIov.iov_len =
            Binding->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
        CxPlatListInitializeHead(&Binding->SocketContexts[i].PendingSendContextHead);
        CxPlatRundownAcquire(&Binding->Rundown);
    }

    CxPlatRundownAcquire(&Datapath->BindingsRundown);

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextInitialize(
                &Binding->SocketContexts[i],
                &Datapath->ProcContexts[i],
                LocalAddress,
                RemoteAddress);
        if (CXPLAT_FAILED(Status)) {
            goto Exit;
        }
    }

    CxPlatConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    for (uint32_t i = 0; i < Binding->Datapath->ProcCount; i++) {
        Status =
            CxPlatSocketContextStartReceive(
                &Binding->SocketContexts[i],
                Datapath->ProcContexts[i].EpollFd);
        if (CXPLAT_FAILED(Status)) {
            goto Exit;
        }
    }

    Status = CXPLAT_STATUS_SUCCESS;

Exit:

    if (CXPLAT_FAILED(Status)) {
        if (Binding != NULL) {
            // TODO - Clean up socket contexts
            CxPlatRundownRelease(&Datapath->BindingsRundown);
            CxPlatRundownUninitialize(&Binding->Rundown);
            CXPLAT_FREE(Binding);
            Binding = NULL;
        }
    }

    return Status;
#endif
}

void
CxPlatDataPathBindingDelete(
    _Inout_ CXPLAT_DATAPATH_BINDING* Binding
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingDelete(Binding);
#else
    CXPLAT_DBG_ASSERT(Binding != NULL);
    CxPlatTraceLogVerbose(
        DatapathShuttingDown,
        "[ udp][%p] Shutting down",
        Binding);

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    Binding->Shutdown = TRUE;
    for (uint32_t i = 0; i < Binding->Datapath->ProcCount; ++i) {
        CxPlatSocketContextUninitialize(
            &Binding->SocketContexts[i],
            &Binding->Datapath->ProcContexts[i]);
    }

    CxPlatRundownReleaseAndWait(&Binding->Rundown);
    CxPlatRundownRelease(&Binding->Datapath->BindingsRundown);

    CxPlatRundownUninitialize(&Binding->Rundown);
    CxPlatFree(Binding);
#endif
}

void
CxPlatDataPathBindingGetLocalAddress(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _Out_ CXPLAT_ADDR* Address
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingGetLocalAddress(Binding, Address);
#else
    CXPLAT_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
#endif
}

void
CxPlatDataPathBindingGetRemoteAddress(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _Out_ CXPLAT_ADDR* Address
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingGetRemoteAddress(Binding, Address);
#else
    CXPLAT_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
#endif
}

CXPLAT_STATUS
CxPlatDataPathBindingSetParam(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSetParam(
            Binding,
            Param,
            BufferLength,
            Buffer);
#else
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return CXPLAT_STATUS_NOT_SUPPORTED;
#endif
}

CXPLAT_STATUS
CxPlatDataPathBindingGetParam(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingGetParam(
            Binding,
            Param,
            BufferLength,
            Buffer);
#else
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return CXPLAT_STATUS_NOT_SUPPORTED;
#endif
}

CXPLAT_RECV_DATAGRAM*
CxPlatDataPathRecvPacketToRecvDatagram(
    _In_ const CXPLAT_RECV_PACKET* const RecvContext
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathRecvContextToRecvPacket(RecvContext);
#else
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        (CXPLAT_DATAPATH_RECV_BLOCK*)
            ((char *)RecvContext - sizeof(CXPLAT_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
#endif
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDatagramToRecvPacket(
    _In_ const CXPLAT_RECV_DATAGRAM* const RecvPacket
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathRecvPacketToRecvContext(RecvPacket);
#else
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        CXPLAT_CONTAINING_RECORD(RecvPacket, CXPLAT_DATAPATH_RECV_BLOCK, RecvPacket);

    return (CXPLAT_RECV_PACKET*)(RecvBlock + 1);
#endif
}

void
CxPlatDataPathBindingReturnRecvDatagrams(
    _In_opt_ CXPLAT_RECV_DATAGRAM* DatagramChain
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    if (DatagramChain != NULL) {
        PlatDispatch->DatapathBindingReturnRecvPacket(DatagramChain);
    }
#else
    CXPLAT_RECV_DATAGRAM* Datagram;
    while ((Datagram = DatagramChain) != NULL) {
        DatagramChain = DatagramChain->Next;
        CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
            CXPLAT_CONTAINING_RECORD(Datagram, CXPLAT_DATAPATH_RECV_BLOCK, RecvPacket);
        CxPlatPoolFree(RecvBlock->OwningPool, RecvBlock);
    }
#endif
}

CXPLAT_DATAPATH_SEND_CONTEXT*
CxPlatDataPathBindingAllocSendContext(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingAllocSendContext(
            Binding,
            MaxPacketSize);
#else
    UNREFERENCED_PARAMETER(MaxPacketSize);
    CXPLAT_DBG_ASSERT(Binding != NULL);

    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext =
        &Binding->Datapath->ProcContexts[CxPlatProcCurrentNumber()];
    CXPLAT_DATAPATH_SEND_CONTEXT* SendContext =
        CxPlatPoolAlloc(&ProcContext->SendContextPool);
    if (SendContext == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH_SEND_CONTEXT",
            0);
        goto Exit;
    }

    CxPlatZeroMemory(SendContext, sizeof(*SendContext));
    SendContext->Owner = ProcContext;
    SendContext->ECN = ECN;

Exit:

    return SendContext;
#endif
}

void
CxPlatDataPathBindingFreeSendContext(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingFreeSendContext(SendContext);
#else
    size_t i = 0;
    for (i = 0; i < SendContext->BufferCount; ++i) {
        CxPlatPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    CxPlatPoolFree(&SendContext->Owner->SendContextPool, SendContext);
#endif
}

CXPLAT_BUFFER*
CxPlatDataPathBindingAllocSendDatagram(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingAllocSendBuffer(
            SendContext,
            MaxBufferLength);
#else
    CXPLAT_BUFFER* Buffer = NULL;

    CXPLAT_DBG_ASSERT(SendContext != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Max batch size limit hit");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    CxPlatZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = CxPlatPoolAlloc(&SendContext->Owner->SendBufferPool);
    if (Buffer->Buffer == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Send Buffer",
            0);
        Buffer = NULL;
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    SendContext->Iovs[SendContext->BufferCount].iov_base = Buffer->Buffer;
    SendContext->Iovs[SendContext->BufferCount].iov_len = Buffer->Length;

    ++SendContext->BufferCount;

Exit:

    return Buffer;
#endif
}

void
CxPlatDataPathBindingFreeSendDatagram(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ CXPLAT_BUFFER* Datagram
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingFreeSendBuffer(SendContext, Datagram);
#else
    CxPlatPoolFree(&SendContext->Owner->SendBufferPool, Datagram->Buffer);
    Datagram->Buffer = NULL;

    CXPLAT_DBG_ASSERT(Datagram == &SendContext->Buffers[SendContext->BufferCount - 1]);

    --SendContext->BufferCount;
#endif
}

CXPLAT_STATUS
CxPlatDataPathBindingSend(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ const CXPLAT_ADDR* LocalAddress,
    _In_ const CXPLAT_ADDR* RemoteAddress,
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSend(
            Binding,
            LocalAddress,
            RemoteAddress,
            SendContext);
#else
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = NULL;
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = NULL;
    ssize_t SentByteCount = 0;
    CXPLAT_ADDR MappedRemoteAddress = {0};
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;

    static_assert(CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)), "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");
    char ControlBuffer[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))] = {0};

    CXPLAT_DBG_ASSERT(Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    SocketContext = &Binding->SocketContexts[CxPlatProcCurrentNumber()];
    ProcContext = &Binding->Datapath->ProcContexts[CxPlatProcCurrentNumber()];

    uint32_t TotalSize = 0;
    for (size_t i = 0; i < SendContext->BufferCount; ++i) {
        SendContext->Iovs[i].iov_base = SendContext->Buffers[i].Buffer;
        SendContext->Iovs[i].iov_len = SendContext->Buffers[i].Length;
        TotalSize += SendContext->Buffers[i].Length;
    }

    CxPlatTraceEvent(
        DatapathSend,
        "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        TotalSize,
        SendContext->BufferCount,
        SendContext->Buffers[0].Length,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

    //
    // Map V4 address to dual-stack socket format.
    //
    CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

    if (MappedRemoteAddress.Ipv6.sin6_family == CXPLAT_ADDRESS_FAMILY_INET6) {
        MappedRemoteAddress.Ipv6.sin6_family = AF_INET6;
    }

    struct msghdr Mhdr = {
        .msg_name = &MappedRemoteAddress,
        .msg_namelen = sizeof(MappedRemoteAddress),
        .msg_iov = SendContext->Iovs,
        .msg_iovlen = SendContext->BufferCount,
        .msg_control = ControlBuffer,
        .msg_controllen = CMSG_SPACE(sizeof(int)),
        .msg_flags = 0
    };

    CMsg = CMSG_FIRSTHDR(&Mhdr);
    CMsg->cmsg_level = RemoteAddress->Ip.sa_family == CXPLAT_ADDRESS_FAMILY_INET ? IPPROTO_IP : IPPROTO_IPV6;
    CMsg->cmsg_type = RemoteAddress->Ip.sa_family == CXPLAT_ADDRESS_FAMILY_INET ? IP_TOS : IPV6_TCLASS;
    CMsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(CMsg) = SendContext->ECN;

    if (!Binding->Connected) {
        Mhdr.msg_controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
        CMsg = CMSG_NXTHDR(&Mhdr, CMsg);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        if (RemoteAddress->Ip.sa_family == CXPLAT_ADDRESS_FAMILY_INET) {
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
            // TODO: Use Ipv4 instead of Ipv6.
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
        } else {
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
        }
    }

    SentByteCount = sendmsg(SocketContext->SocketFd, &Mhdr, 0);

    if (SentByteCount < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            Status =
                CxPlatSocketContextPendSend(
                    SocketContext,
                    SendContext,
                    ProcContext,
                    LocalAddress,
                    RemoteAddress);
            if (CXPLAT_FAILED(Status)) {
                goto Exit;
            }

            SendPending = TRUE;
            goto Exit;
        } else {
            Status = errno;
            CxPlatTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                Status,
                "sendmsg failed");
            goto Exit;
        }
    }

    Status = CXPLAT_STATUS_SUCCESS;

Exit:

    if (!SendPending) {
        CxPlatDataPathBindingFreeSendContext(SendContext);
    }

    return Status;
#endif // CXPLAT_PLATFORM_DISPATCH_TABLE
}

uint16_t
CxPlatDataPathBindingGetLocalMtu(
    _In_ CXPLAT_DATAPATH_BINDING* Binding
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingGetLocalMtu(Binding);
#else
    CXPLAT_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
#endif
}

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)                              \
    ({                                                              \
        long int FailureRetryResult = 0;                            \
        do {                                                        \
            FailureRetryResult = (long int)(expression);            \
        } while ((FailureRetryResult == -1L) && (errno == EINTR));  \
        FailureRetryResult;                                         \
    })
#endif

void*
CxPlatDataPathWorkerThread(
    _In_ void* Context
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = (CXPLAT_DATAPATH_PROC_CONTEXT*)Context;
    CXPLAT_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);

    CxPlatTraceLogInfo(
        DatapathWorkerThreadStart,
        "[ udp][%p] Worker start",
        ProcContext);

    const size_t EpollEventCtMax = 16; // TODO: Experiment.
    struct epoll_event EpollEvents[EpollEventCtMax];

    while (!ProcContext->Datapath->Shutdown) {
        int ReadyEventCount =
            TEMP_FAILURE_RETRY(
                epoll_wait(
                    ProcContext->EpollFd,
                    EpollEvents,
                    EpollEventCtMax,
                    -1));

        CXPLAT_FRE_ASSERT(ReadyEventCount >= 0);
        for (int i = 0; i < ReadyEventCount; i++) {
            if (EpollEvents[i].data.ptr == NULL) {
                //
                // The processor context is shutting down and the worker thread
                // needs to clean up.
                //
                CXPLAT_DBG_ASSERT(ProcContext->Datapath->Shutdown);
                break;
            }

            CxPlatSocketContextProcessEvents(
                EpollEvents[i].data.ptr,
                ProcContext,
                EpollEvents[i].events);
        }
    }

    CxPlatTraceLogInfo(
        DatapathWorkerThreadStop,
        "[ udp][%p] Worker stop",
        ProcContext);

    return NO_ERROR;
}

BOOLEAN
CxPlatDataPathBindingIsSendContextFull(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef CXPLAT_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingIsSendContextFull(SendContext);
#else
    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
#endif
}
