/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for the data path used by the core QUIC
    library.

--*/

#pragma once

#include "quic_platform.h"

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(disable:4200)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:4214)  // nonstandard extension used: bit field types other than int

//
// The minimum IPv4 header size.
//
#define CXPLAT_MIN_IPV4_HEADER_SIZE 20

//
// The minimum IPv6 header size.
//
#define CXPLAT_MIN_IPV6_HEADER_SIZE 40

//
// The number of bytes in a UDP header.
//
#define CXPLAT_UDP_HEADER_SIZE 8

typedef enum CXPLAT_ECN_TYPE {

    CXPLAT_ECN_NON_ECT = 0x0, // Non ECN-Capable Transport, Non-ECT
    CXPLAT_ECN_ECT_1   = 0x1, // ECN Capable Transport, ECT(1)
    CXPLAT_ECN_ECT_0   = 0x2, // ECN Capable Transport, ECT(0)
    CXPLAT_ECN_CE      = 0x3  // Congestion Encountered, CE

} CXPLAT_ECN_TYPE;

//
// Helper to get the ECN type from the Type of Service field of a recieved
// datagram.
//
#define CXPLAT_ECN_FROM_TOS(ToS) (CXPLAT_ECN_TYPE)((ToS) & 0x3)

//
// The minimum allowed IP MTU for QUIC.
//
#define CXPLAT_MIN_MTU 1280

//
// The maximum IP MTU this implementation supports for QUIC.
//
#define CXPLAT_MAX_MTU 1500

//
// The buffer size that must be allocated to fit the maximum UDP payload we
// support.
//
#define MAX_UDP_PAYLOAD_LENGTH (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE)

//
// Helper function for calculating the length of a UDP packet, for a given
// MTU, on a dual-mode socket. It uses IPv4 header size since that is the
// least limiting as far as making sure enough space is allocated. An IPv6
// UDP payload can still fit in a buffer allocated for IPv4, but not the
// reverse.
//
inline
uint16_t
MaxUdpPayloadSizeFromMTU(
    _In_ uint16_t Mtu
    )
{
    return  Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
}

//
// Helper function for calculating the length of UDP payload, given the address
// family and MTU.
//
inline
uint16_t
MaxUdpPayloadSizeForFamily(
    _In_ CXPLAT_ADDRESS_FAMILY Family,
    _In_ uint16_t Mtu
    )
{
    return Family == CXPLAT_ADDRESS_FAMILY_INET ?
        Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE :
        Mtu - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
}

//
// Helper function for calculating the MTU, given the length of UDP payload and
// the address family.
//
inline
uint16_t
PacketSizeFromUdpPayloadSize(
    _In_ CXPLAT_ADDRESS_FAMILY Family,
    _In_ uint16_t UdpPayloadSize
    )
{
    return Family == CXPLAT_ADDRESS_FAMILY_INET ?
        UdpPayloadSize + CXPLAT_MIN_IPV4_HEADER_SIZE + CXPLAT_UDP_HEADER_SIZE :
        UdpPayloadSize + CXPLAT_MIN_IPV6_HEADER_SIZE + CXPLAT_UDP_HEADER_SIZE;
}

typedef struct CXPLAT_BUFFER CXPLAT_BUFFER;

//
// Declaration for the DataPath context structures.
//
typedef struct CXPLAT_DATAPATH CXPLAT_DATAPATH;
typedef struct CXPLAT_DATAPATH_BINDING CXPLAT_DATAPATH_BINDING;

//
// Can be defined to whatever the client needs.
//
typedef struct CXPLAT_RECV_PACKET CXPLAT_RECV_PACKET;

//
// Structure to represent data buffers received.
//
typedef struct CXPLAT_TUPLE {

    CXPLAT_ADDR RemoteAddress;
    CXPLAT_ADDR LocalAddress;

} CXPLAT_TUPLE;

//
// Structure to represent received UDP datagrams.
//
typedef struct CXPLAT_RECV_DATAGRAM {

    //
    // The next receive datagram in the chain.
    //
    struct CXPLAT_RECV_DATAGRAM* Next;

    //
    // Contains the 4 tuple.
    //
    CXPLAT_TUPLE* Tuple;

    //
    // The data buffer containing the received bytes.
    //
    _Field_size_(BufferLength)
    uint8_t * Buffer;

    //
    // Length of the valid data in Buffer.
    //
    uint16_t BufferLength;

    //
    // The partition ID of the received datagram.
    //
    uint16_t PartitionIndex;

    //
    // The Type of Service (ToS) field of the IPv4 header or Traffic Class field
    // of the IPv6 header.
    //
    uint8_t TypeOfService;

    //
    // Flags.
    //
    uint8_t Allocated : 1;          // Used for debugging. Set to FALSE on free.
    uint8_t QueuedOnConnection : 1; // Used for debugging.

} CXPLAT_RECV_DATAGRAM;

//
// Gets the corresponding recv datagram from its context pointer.
//
CXPLAT_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const CXPLAT_RECV_PACKET* const Packet
    );

//
// Gets the corresponding client context from its recv datagram pointer.
//
CXPLAT_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const CXPLAT_RECV_DATAGRAM* const Datagram
    );

//
// Function pointer type for Datapath receive callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_RECEIVE_CALLBACK)
void
(CXPLAT_DATAPATH_RECEIVE_CALLBACK)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATAGRAM* DatagramChain
    );

typedef CXPLAT_DATAPATH_RECEIVE_CALLBACK *CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER;

//
// Function pointer type for Datapath port unreachable callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)
void
(CXPLAT_DATAPATH_UNREACHABLE_CALLBACK)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ const CXPLAT_ADDR* RemoteAddress
    );

typedef CXPLAT_DATAPATH_UNREACHABLE_CALLBACK *CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER;


//
// Function pointer type for send complete callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_DATAPATH_SEND_COMPLETE)
void
(CXPLAT_DATAPATH_SEND_COMPLETE)(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ void* ClientContext,
    _In_ CXPLAT_STATUS CompletionStatus,
    _In_ uint32_t NumBytesSent
    );

typedef CXPLAT_DATAPATH_SEND_COMPLETE *CXPLAT_DATAPATH_SEND_COMPLETE_HANDLER;

//
// Structure that maintains the 'per send' context for QuicDataPath.
//
typedef struct CXPLAT_DATAPATH_SEND_CONTEXT CXPLAT_DATAPATH_SEND_CONTEXT;

//
// Opens a new handle to the QUIC Datapath library.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ CXPLAT_DATAPATH* *NewDatapath
    );

//
// Closes a QUIC Datapath library handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    );

#define CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING     0x0001
#define CXPLAT_DATAPATH_FEATURE_RECV_COALESCING       0x0002
#define CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION     0x0004

//
// Queries the currently supported features of the datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    );

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    );

//
// Resolves a hostname to an IP address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
QuicDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ CXPLAT_ADDR* Address
    );

//
// The following APIs are specific to a single UDP port abstraction.
//

//
// Creates a datapath binding handle for the given local address and/or remote
// address. This function immediately registers for receive upcalls from the
// UDP layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
QuicDataPathBindingCreate(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const CXPLAT_ADDR* LocalAddress,
    _In_opt_ const CXPLAT_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_DATAPATH_BINDING** Binding
    );

//
// Deletes a UDP binding. This function blocks on all outstandind upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDelete(
    _In_ CXPLAT_DATAPATH_BINDING* Binding
    );

//
// Queries the locally bound interface's MTU. Returns CXPLAT_MIN_MTU if not
// already bound.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicDataPathBindingGetLocalMtu(
    _In_ CXPLAT_DATAPATH_BINDING* Binding
    );

//
// Queries the locally bound IP address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetLocalAddress(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _Out_ CXPLAT_ADDR* Address
    );

//
// Queries the connected remote IP address. Only valid if the binding was
// initially created with a remote address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetRemoteAddress(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _Out_ CXPLAT_ADDR* Address
    );

//
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ CXPLAT_RECV_DATAGRAM* DatagramChain
    );

//
// Allocates a new send context to be used to call QuicDataPathBindingSend. It
// can be freed with QuicDataPathBindingFreeSendContext too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    );

//
// Frees a send context returned from a previous call to
// QuicDataPathBindingAllocSendContext.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendContext(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

//
// Allocates a new UDP datagram buffer for sending.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    );

//
// Frees a datagram buffer returned from a previous call to
// QuicDataPathBindingAllocSendDatagram.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendDatagram(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ CXPLAT_BUFFER* SendDatagram
    );

//
// Returns whether the send context buffer limit has been reached.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
QuicDataPathBindingSend(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ const CXPLAT_ADDR* LocalAddress,
    _In_ const CXPLAT_ADDR* RemoteAddress,
    _In_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
QuicDataPathBindingSetParam(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    );

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
QuicDataPathBindingGetParam(
    _In_ CXPLAT_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    );

#if defined(__cplusplus)
}
#endif
