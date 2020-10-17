/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Declarations for the CxPlat API, which enables applications and drivers to
    create QUIC connections as a client or server.

    For more detailed information, see ../docs/API.md

Supported Platforms:

    Windows User mode
    Windows Kernel mode
    Linux User mode

--*/

#ifndef _MSCXPLAT_
#define _MSCXPLAT_

#ifdef _WIN32
#pragma once
#endif

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4214)  // nonstandard extension used: bit field types other than int

#ifdef _KERNEL_MODE
#include "cxplat_winkernel.h"
#elif _WIN32
#include "cxplat_winuser.h"
#elif __linux__
#include "cxplat_linux.h"
#else
#error "Unsupported Platform"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_HANDLE *HQUIC;

//
// The maximum value that can be encoded in a 62-bit integer.
//
#define CXPLAT_UINT62_MAX ((1ULL << 62) - 1)

//
// Represents a 62-bit integer.
//
typedef _In_range_(0, CXPLAT_UINT62_MAX) uint64_t CXPLAT_UINT62;

//
// An ALPN must not exceed 255 bytes, and must not be zero-length.
//
#define CXPLAT_MAX_ALPN_LENGTH            255

//
// A server name must not exceed 65535 bytes.
//
#define CXPLAT_MAX_SNI_LENGTH             65535

//
// The maximum number of bytes of application data a server application can
// send in a resumption ticket.
//
#define CXPLAT_MAX_RESUMPTION_APP_DATA_LENGTH     1000

typedef enum CXPLAT_EXECUTION_PROFILE {
    CXPLAT_EXECUTION_PROFILE_LOW_LATENCY,         // Default
    CXPLAT_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT,
    CXPLAT_EXECUTION_PROFILE_TYPE_SCAVENGER,
    CXPLAT_EXECUTION_PROFILE_TYPE_REAL_TIME
} CXPLAT_EXECUTION_PROFILE;

typedef enum CXPLAT_LOAD_BALANCING_MODE {
    CXPLAT_LOAD_BALANCING_DISABLED,               // Default
    CXPLAT_LOAD_BALANCING_SERVER_ID_IP            // Encodes IP address in Server ID
} CXPLAT_LOAD_BALANCING_MODE;

typedef enum CXPLAT_CREDENTIAL_TYPE {
    CXPLAT_CREDENTIAL_TYPE_NONE,
    CXPLAT_CREDENTIAL_TYPE_CERTIFICATE_HASH,
    CXPLAT_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE,
    CXPLAT_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
    CXPLAT_CREDENTIAL_TYPE_CERTIFICATE_FILE
} CXPLAT_CREDENTIAL_TYPE;

typedef enum CXPLAT_CREDENTIAL_FLAGS {
    CXPLAT_CREDENTIAL_FLAG_NONE                       = 0x00000000,
    CXPLAT_CREDENTIAL_FLAG_CLIENT                     = 0x00000001, // Lack of client flag indicates server.
    CXPLAT_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS          = 0x00000002,
    CXPLAT_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION  = 0x00000004,
    CXPLAT_CREDENTIAL_FLAG_ENABLE_OCSP                = 0x00000008
} CXPLAT_CREDENTIAL_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_CREDENTIAL_FLAGS);

typedef enum CXPLAT_CERTIFICATE_HASH_STORE_FLAGS {
    CXPLAT_CERTIFICATE_HASH_STORE_FLAG_NONE           = 0x0000,
    CXPLAT_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE  = 0x0001
} CXPLAT_CERTIFICATE_HASH_STORE_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_CERTIFICATE_HASH_STORE_FLAGS);

typedef enum CXPLAT_CONNECTION_SHUTDOWN_FLAGS {
    CXPLAT_CONNECTION_SHUTDOWN_FLAG_NONE      = 0x0000,
    CXPLAT_CONNECTION_SHUTDOWN_FLAG_SILENT    = 0x0001    // Don't send the close frame over the network.
} CXPLAT_CONNECTION_SHUTDOWN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_CONNECTION_SHUTDOWN_FLAGS);

typedef enum CXPLAT_SERVER_RESUMPTION_LEVEL {
    CXPLAT_SERVER_NO_RESUME,
    CXPLAT_SERVER_RESUME_ONLY,
    CXPLAT_SERVER_RESUME_AND_ZERORTT
} CXPLAT_SERVER_RESUMPTION_LEVEL;

typedef enum CXPLAT_SEND_RESUMPTION_FLAGS {
    CXPLAT_SEND_RESUMPTION_FLAG_NONE          = 0x0000,
    CXPLAT_SEND_RESUMPTION_FLAG_FINAL         = 0x0001    // Free TLS state after sending this ticket.
} CXPLAT_SEND_RESUMPTION_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_SEND_RESUMPTION_FLAGS);

typedef enum CXPLAT_STREAM_SCHEDULING_SCHEME {
    CXPLAT_STREAM_SCHEDULING_SCHEME_FIFO          = 0x0000,   // Sends stream data first come, first served. (Default)
    CXPLAT_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN   = 0x0001,   // Sends stream data evenly multiplexed.
    CXPLAT_STREAM_SCHEDULING_SCHEME_COUNT                     // The number of stream scheduling schemes.
} CXPLAT_STREAM_SCHEDULING_SCHEME;

typedef enum CXPLAT_STREAM_OPEN_FLAGS {
    CXPLAT_STREAM_OPEN_FLAG_NONE              = 0x0000,
    CXPLAT_STREAM_OPEN_FLAG_UNIDIRECTIONAL    = 0x0001,   // Indicates the stream is unidirectional.
    CXPLAT_STREAM_OPEN_FLAG_0_RTT             = 0x0002    // The stream was opened via a 0-RTT packet.
} CXPLAT_STREAM_OPEN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_STREAM_OPEN_FLAGS);

typedef enum CXPLAT_STREAM_START_FLAGS {
    CXPLAT_STREAM_START_FLAG_NONE             = 0x0000,
    CXPLAT_STREAM_START_FLAG_FAIL_BLOCKED     = 0x0001,   // Only opens the stream if flow control allows.
    CXPLAT_STREAM_START_FLAG_IMMEDIATE        = 0x0002,   // Immediately informs peer that stream is open.
    CXPLAT_STREAM_START_FLAG_ASYNC            = 0x0004    // Don't block the API call to wait for completion.
} CXPLAT_STREAM_START_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_STREAM_START_FLAGS);

typedef enum CXPLAT_STREAM_SHUTDOWN_FLAGS {
    CXPLAT_STREAM_SHUTDOWN_FLAG_NONE          = 0x0000,
    CXPLAT_STREAM_SHUTDOWN_FLAG_GRACEFUL      = 0x0001,   // Cleanly closes the send path.
    CXPLAT_STREAM_SHUTDOWN_FLAG_ABORT_SEND    = 0x0002,   // Abruptly closes the send path.
    CXPLAT_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE = 0x0004,   // Abruptly closes the receive path.
    CXPLAT_STREAM_SHUTDOWN_FLAG_ABORT         = 0x0006,   // Abruptly closes both send and receive paths.
    CXPLAT_STREAM_SHUTDOWN_FLAG_IMMEDIATE     = 0x0008    // Immediately sends completion events to app.
} CXPLAT_STREAM_SHUTDOWN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_STREAM_SHUTDOWN_FLAGS);

typedef enum CXPLAT_RECEIVE_FLAGS {
    CXPLAT_RECEIVE_FLAG_NONE                  = 0x0000,
    CXPLAT_RECEIVE_FLAG_0_RTT                 = 0x0001,   // Data was encrypted with 0-RTT key.
    CXPLAT_RECEIVE_FLAG_FIN                   = 0x0002    // FIN was included with this data.
} CXPLAT_RECEIVE_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_RECEIVE_FLAGS);

typedef enum CXPLAT_SEND_FLAGS {
    CXPLAT_SEND_FLAG_NONE                     = 0x0000,
    CXPLAT_SEND_FLAG_ALLOW_0_RTT              = 0x0001,   // Allows the use of encrypting with 0-RTT key.
    CXPLAT_SEND_FLAG_START                    = 0x0002,   // Asynchronously starts the stream with the sent data.
    CXPLAT_SEND_FLAG_FIN                      = 0x0004,   // Indicates the request is the one last sent on the stream.
    CXPLAT_SEND_FLAG_DGRAM_PRIORITY           = 0x0008    // Indicates the datagram is higher priority than others.
} CXPLAT_SEND_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CXPLAT_SEND_FLAGS);

typedef enum CXPLAT_DATAGRAM_SEND_STATE {
    CXPLAT_DATAGRAM_SEND_SENT,                            // Sent and awaiting acknowledegment
    CXPLAT_DATAGRAM_SEND_LOST_SUSPECT,                    // Suspected as lost, but still tracked
    CXPLAT_DATAGRAM_SEND_LOST_DISCARDED,                  // Lost and not longer being tracked
    CXPLAT_DATAGRAM_SEND_ACKNOWLEDGED,                    // Acknowledged
    CXPLAT_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS,           // Acknowledged after being suspected lost
    CXPLAT_DATAGRAM_SEND_CANCELED                         // Canceled before send
} CXPLAT_DATAGRAM_SEND_STATE;

//
// Helper to determine if a datagrams state is final, and no longer tracked
// by CxPlat.
//
#define CXPLAT_DATAGRAM_SEND_STATE_IS_FINAL(State) \
    (State >= CXPLAT_DATAGRAM_SEND_LOST_DISCARDED)


typedef struct CXPLAT_REGISTRATION_CONFIG { // All fields may be NULL/zero.
    const char* AppName;
    CXPLAT_EXECUTION_PROFILE ExecutionProfile;
} CXPLAT_REGISTRATION_CONFIG;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_CREDENTIAL_LOAD_COMPLETE)
void
(CXPLAT_API CXPLAT_CREDENTIAL_LOAD_COMPLETE)(
    _In_ HQUIC Configuration,
    _In_opt_ void* Context,
    _In_ CXPLAT_STATUS Status
    );

typedef CXPLAT_CREDENTIAL_LOAD_COMPLETE *CXPLAT_CREDENTIAL_LOAD_COMPLETE_HANDLER;

typedef struct CXPLAT_CERTIFICATE_HASH {
    uint8_t ShaHash[20];
} CXPLAT_CERTIFICATE_HASH;

typedef struct CXPLAT_CERTIFICATE_HASH_STORE {
    CXPLAT_CERTIFICATE_HASH_STORE_FLAGS Flags;
    uint8_t ShaHash[20];
    char StoreName[128];
} CXPLAT_CERTIFICATE_HASH_STORE;

typedef struct CXPLAT_CERTIFICATE_FILE {
    const char *PrivateKeyFile;
    const char *CertificateFile;
} CXPLAT_CERTIFICATE_FILE;

typedef void CXPLAT_CERTIFICATE; // Platform specific certificate context object

typedef struct CXPLAT_CREDENTIAL_CONFIG {
    CXPLAT_CREDENTIAL_TYPE Type;
    CXPLAT_CREDENTIAL_FLAGS Flags;
    union {
        CXPLAT_CERTIFICATE_HASH* CertificateHash;
        CXPLAT_CERTIFICATE_HASH_STORE* CertificateHashStore;
        CXPLAT_CERTIFICATE* CertificateContext;
        CXPLAT_CERTIFICATE_FILE* CertificateFile;
    };
    const char* Principal;
    void* TicketKey; // Optional, 44 byte array
    CXPLAT_CREDENTIAL_LOAD_COMPLETE_HANDLER AsyncHandler; // Optional
} CXPLAT_CREDENTIAL_CONFIG;

//
// A single contiguous buffer.
//
typedef struct CXPLAT_BUFFER {
    uint32_t Length;
    _Field_size_bytes_(Length)
    uint8_t* Buffer;
} CXPLAT_BUFFER;

//
// All the available information describing a new incoming connection.
//
typedef struct CXPLAT_NEW_CONNECTION_INFO {
    uint32_t QuicVersion;
    const CXPLAT_ADDR* LocalAddress;
    const CXPLAT_ADDR* RemoteAddress;
    uint32_t CryptoBufferLength;
    uint16_t ClientAlpnListLength;
    uint16_t ServerNameLength;
    uint8_t NegotiatedAlpnLength;
    _Field_size_bytes_(CryptoBufferLength)
    const uint8_t* CryptoBuffer;
    _Field_size_bytes_(ClientAlpnListLength)
    const uint8_t* ClientAlpnList;
    _Field_size_bytes_(NegotiatedAlpnLength)
    const uint8_t* NegotiatedAlpn;
    _Field_size_bytes_opt_(ServerNameLength)
    const char* ServerName;
} CXPLAT_NEW_CONNECTION_INFO;

//
// All statistics available to query about a connection.
//
typedef struct CXPLAT_STATISTICS {
    uint64_t CorrelationId;
    uint32_t VersionNegotiation     : 1;
    uint32_t StatelessRetry         : 1;
    uint32_t ResumptionAttempted    : 1;
    uint32_t ResumptionSucceeded    : 1;
    uint32_t Rtt;                       // In microseconds
    uint32_t MinRtt;                    // In microseconds
    uint32_t MaxRtt;                    // In microseconds
    struct {
        uint64_t Start;
        uint64_t InitialFlightEnd;      // Processed all peer's Initial packets
        uint64_t HandshakeFlightEnd;    // Processed all peer's Handshake packets
    } Timing;
    struct {
        uint32_t ClientFlight1Bytes;    // Sum of TLS payloads
        uint32_t ServerFlight1Bytes;    // Sum of TLS payloads
        uint32_t ClientFlight2Bytes;    // Sum of TLS payloads
    } Handshake;
    struct {
        uint16_t PathMtu;               // Current path MTU.
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t RetransmittablePackets;
        uint64_t SuspectedLostPackets;
        uint64_t SpuriousLostPackets;   // Actual lost is (SuspectedLostPackets - SpuriousLostPackets)
        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
        uint32_t CongestionCount;       // Number of congestion events
        uint32_t PersistentCongestionCount; // Number of persistent congestion events
    } Send;
    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t ReorderedPackets;      // Packets where packet number is less than highest seen.
        uint64_t DroppedPackets;        // Includes DuplicatePackets.
        uint64_t DuplicatePackets;
        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
        uint64_t DecryptionFailures;    // Count of packet decryption failures.
        uint64_t ValidAckFrames;        // Count of receive ACK frames.
    } Recv;
    struct {
        uint32_t KeyUpdateCount;
    } Misc;
} CXPLAT_STATISTICS;

typedef struct CXPLAT_LISTENER_STATISTICS {

    uint64_t TotalAcceptedConnections;
    uint64_t TotalRejectedConnections;

    struct {
        struct {
            uint64_t DroppedPackets;
        } Recv;
    } Binding;
} CXPLAT_LISTENER_STATISTICS;

typedef enum CXPLAT_PERFORMANCE_COUNTERS {
    CXPLAT_PERF_COUNTER_CONN_CREATED,         // Total connections ever allocated.
    CXPLAT_PERF_COUNTER_CONN_HANDSHAKE_FAIL,  // Total connections that failed during handshake.
    CXPLAT_PERF_COUNTER_CONN_APP_REJECT,      // Total connections rejected by the application.
    CXPLAT_PERF_COUNTER_CONN_RESUMED,         // Total connections resumed.
    CXPLAT_PERF_COUNTER_CONN_ACTIVE,          // Connections currently allocated.
    CXPLAT_PERF_COUNTER_CONN_CONNECTED,       // Connections currently in the connected state.
    CXPLAT_PERF_COUNTER_CONN_PROTOCOL_ERRORS, // Total connections shutdown with a protocol error.
    CXPLAT_PERF_COUNTER_CONN_NO_ALPN,         // Total connection attempts with no matching ALPN.
    CXPLAT_PERF_COUNTER_STRM_ACTIVE,          // Current streams allocated.
    CXPLAT_PERF_COUNTER_PKTS_SUSPECTED_LOST,  // Total suspected packets lost
    CXPLAT_PERF_COUNTER_PKTS_DROPPED,         // Total packets dropped for any reason.
    CXPLAT_PERF_COUNTER_PKTS_DECRYPTION_FAIL, // Total packets with decryption failures.
    CXPLAT_PERF_COUNTER_UDP_RECV,             // Total UDP datagrams received.
    CXPLAT_PERF_COUNTER_UDP_SEND,             // Total UDP datagrams sent.
    CXPLAT_PERF_COUNTER_UDP_RECV_BYTES,       // Total UDP payload bytes received.
    CXPLAT_PERF_COUNTER_UDP_SEND_BYTES,       // Total UDP payload bytes sent.
    CXPLAT_PERF_COUNTER_UDP_RECV_EVENTS,      // Total UDP receive events.
    CXPLAT_PERF_COUNTER_UDP_SEND_CALLS,       // Total UDP send API calls.
    CXPLAT_PERF_COUNTER_APP_SEND_BYTES,       // Total bytes sent by applications.
    CXPLAT_PERF_COUNTER_APP_RECV_BYTES,       // Total bytes received by applications.
    CXPLAT_PERF_COUNTER_CONN_QUEUE_DEPTH,     // Current connections queued for processing.
    CXPLAT_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH,// Current connection operations queued.
    CXPLAT_PERF_COUNTER_CONN_OPER_QUEUED,     // Total connection operations queued ever.
    CXPLAT_PERF_COUNTER_CONN_OPER_COMPLETED,  // Total connection operations processed ever.
    CXPLAT_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH,// Current worker operations queued.
    CXPLAT_PERF_COUNTER_WORK_OPER_QUEUED,     // Total worker operations queued ever.
    CXPLAT_PERF_COUNTER_WORK_OPER_COMPLETED,  // Total worker operations processed ever.
    CXPLAT_PERF_COUNTER_MAX
} CXPLAT_PERFORMANCE_COUNTERS;

typedef struct CXPLAT_SETTINGS {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey             : 1;
            uint64_t HandshakeIdleTimeoutMs     : 1;
            uint64_t IdleTimeoutMs              : 1;
            uint64_t TlsClientMaxSendBuffer     : 1;
            uint64_t TlsServerMaxSendBuffer     : 1;
            uint64_t StreamRecvWindowDefault    : 1;
            uint64_t StreamRecvBufferDefault    : 1;
            uint64_t ConnFlowControlWindow      : 1;
            uint64_t MaxWorkerQueueDelayUs      : 1;
            uint64_t MaxStatelessOperations     : 1;
            uint64_t InitialWindowPackets       : 1;
            uint64_t SendIdleTimeoutMs          : 1;
            uint64_t InitialRttMs               : 1;
            uint64_t MaxAckDelayMs              : 1;
            uint64_t DisconnectTimeoutMs        : 1;
            uint64_t KeepAliveIntervalMs        : 1;
            uint64_t PeerBidiStreamCount        : 1;
            uint64_t PeerUnidiStreamCount       : 1;
            uint64_t RetryMemoryLimit           : 1;
            uint64_t LoadBalancingMode          : 1;
            uint64_t MaxOperationsPerDrain      : 1;
            uint64_t SendBufferingEnabled       : 1;
            uint64_t PacingEnabled              : 1;
            uint64_t MigrationEnabled           : 1;
            uint64_t DatagramReceiveEnabled     : 1;
            uint64_t ServerResumptionLevel      : 1;
            uint64_t RESERVED                   : 38;
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t RetryMemoryLimit;              // Global only
    uint16_t LoadBalancingMode;             // Global only
    uint8_t MaxOperationsPerDrain;
    uint8_t SendBufferingEnabled    : 1;
    uint8_t PacingEnabled           : 1;
    uint8_t MigrationEnabled        : 1;
    uint8_t DatagramReceiveEnabled  : 1;
    uint8_t ServerResumptionLevel   : 2;    // CXPLAT_SERVER_RESUMPTION_LEVEL
    uint8_t RESERVED                : 2;

} CXPLAT_SETTINGS;

//
// Functions for associating application contexts with QUIC handles.
//

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(CXPLAT_API * CXPLAT_SET_CONTEXT_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ void* Context
    );

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void*
(CXPLAT_API * CXPLAT_GET_CONTEXT_FN)(
    _In_ _Pre_defensive_ HQUIC Handle
    );

//
// Sets the event handler for the QUIC handle. The type of the handler must be
// appropriate for the type of the handle.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(CXPLAT_API * CXPLAT_SET_CALLBACK_HANDLER_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ void* Handler,
    _In_opt_ void* Context
    );

//
// Get and Set parameters on a handle.
//

typedef enum CXPLAT_PARAM_LEVEL {
    CXPLAT_PARAM_LEVEL_GLOBAL,
    CXPLAT_PARAM_LEVEL_REGISTRATION,
    CXPLAT_PARAM_LEVEL_CONFIGURATION,
    CXPLAT_PARAM_LEVEL_LISTENER,
    CXPLAT_PARAM_LEVEL_CONNECTION,
    CXPLAT_PARAM_LEVEL_TLS,
    CXPLAT_PARAM_LEVEL_STREAM
} CXPLAT_PARAM_LEVEL;

//
// Parameters for CXPLAT_PARAM_LEVEL_GLOBAL.
//
#define CXPLAT_PARAM_GLOBAL_RETRY_MEMORY_PERCENT          0   // uint16_t
#define CXPLAT_PARAM_GLOBAL_SUPPORTED_VERSIONS            1   // uint32_t[] - network byte order
#define CXPLAT_PARAM_GLOBAL_LOAD_BALACING_MODE            2   // uint16_t - CXPLAT_LOAD_BALANCING_MODE
#define CXPLAT_PARAM_GLOBAL_PERF_COUNTERS                 3   // uint64_t[] - Array size is CXPLAT_PERF_COUNTER_MAX
#define CXPLAT_PARAM_GLOBAL_SETTINGS                      4   // CXPLAT_SETTINGS

//
// Parameters for CXPLAT_PARAM_LEVEL_REGISTRATION.
//
#define CXPLAT_PARAM_REGISTRATION_CID_PREFIX              0   // uint8_t[]

//
// Parameters for CXPLAT_PARAM_LEVEL_CONFIGURATION.
//
#define CXPLAT_PARAM_CONFIGURATION_SETTINGS               0   // CXPLAT_SETTINGS

//
// Parameters for CXPLAT_PARAM_LEVEL_LISTENER.
//
#define CXPLAT_PARAM_LISTENER_LOCAL_ADDRESS               0   // CXPLAT_ADDR
#define CXPLAT_PARAM_LISTENER_STATS                       1   // CXPLAT_LISTENER_STATISTICS

//
// Parameters for CXPLAT_PARAM_LEVEL_CONNECTION.
//
#define CXPLAT_PARAM_CONN_CXPLAT_VERSION                    0   // uint32_t
#define CXPLAT_PARAM_CONN_LOCAL_ADDRESS                   1   // CXPLAT_ADDR
#define CXPLAT_PARAM_CONN_REMOTE_ADDRESS                  2   // CXPLAT_ADDR
#define CXPLAT_PARAM_CONN_IDEAL_PROCESSOR                 3   // uint16_t
#define CXPLAT_PARAM_CONN_SETTINGS                        4   // CXPLAT_SETTINGS
#define CXPLAT_PARAM_CONN_STATISTICS                      5   // CXPLAT_STATISTICS
#define CXPLAT_PARAM_CONN_STATISTICS_PLAT                 6   // CXPLAT_STATISTICS
#define CXPLAT_PARAM_CONN_SHARE_UDP_BINDING               7   // uint8_t (BOOLEAN)
#define CXPLAT_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT         8   // uint16_t
#define CXPLAT_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT        9   // uint16_t
#define CXPLAT_PARAM_CONN_MAX_STREAM_IDS                  10  // uint64_t[4]
#define CXPLAT_PARAM_CONN_CLOSE_REASON_PHRASE             11  // char[]
#define CXPLAT_PARAM_CONN_STREAM_SCHEDULING_SCHEME        12  // CXPLAT_STREAM_SCHEDULING_SCHEME
#define CXPLAT_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED        13  // uint8_t (BOOLEAN)
#define CXPLAT_PARAM_CONN_DATAGRAM_SEND_ENABLED           14  // uint8_t (BOOLEAN)
#ifdef CXPLAT_API_ENABLE_INSECURE_FEATURES
#define CXPLAT_PARAM_CONN_DISABLE_1RTT_ENCRYPTION         15  // uint8_t (BOOLEAN)
#endif
#define CXPLAT_PARAM_CONN_RESUMPTION_TICKET               16  // uint8_t[]

//
// Parameters for CXPLAT_PARAM_LEVEL_TLS.
//
#ifdef WIN32 // Windows Platform specific parameters
typedef struct CXPLAT_SCHANNEL_CONTEXT_ATTRIBUTE_W {
    unsigned long Attribute;
    void* Buffer;
} CXPLAT_SCHANNEL_CONTEXT_ATTRIBUTE_W;
#define CXPLAT_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W     0x1000000   // CXPLAT_SCHANNEL_CONTEXT_ATTRIBUTE_W
#endif

//
// Parameters for CXPLAT_PARAM_LEVEL_STREAM.
//
#define CXPLAT_PARAM_STREAM_ID                            0   // CXPLAT_UINT62
#define CXPLAT_PARAM_STREAM_0RTT_LENGTH                   1   // uint64_t
#define CXPLAT_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE        2   // uint64_t - bytes

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_SET_PARAM_FN)(
    _When_(Level == CXPLAT_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != CXPLAT_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ CXPLAT_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_GET_PARAM_FN)(
    _When_(Level == CXPLAT_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != CXPLAT_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ CXPLAT_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );

//
// Registration Context Interface.
//

//
// Opens a new registration.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_REGISTRATION_OPEN_FN)(
    _In_opt_ const CXPLAT_REGISTRATION_CONFIG* Config,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    );

//
// Closes the registration. This function synchronizes the cleanup of all
// child objects. It does this by blocking until all those child objects have
// been closed by the application.
// N.B. This function will deadlock if called in any CxPlat callbacks.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_API * CXPLAT_REGISTRATION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Registration
    );

//
// Calls shutdown for all connections in this registration. Don't call on a
// CxPlat callback thread or it might deadlock.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(CXPLAT_API * CXPLAT_REGISTRATION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ CXPLAT_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ CXPLAT_UINT62 ErrorCode // Application defined error code
    );

//
// Configuration Interface.
//

//
// Opens a new configuration.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_CONFIGURATION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const CXPLAT_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_reads_bytes_opt_(SettingsSize)
        const CXPLAT_SETTINGS* Settings,
    _In_ uint32_t SettingsSize,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Configuration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Configuration
    );

//
// Closes an existing configuration.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_API * CXPLAT_CONFIGURATION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Configuration
    );

//
// Loads the credentials based on the input configuration.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_CONFIGURATION_LOAD_CREDENTIAL_FN)(
    _In_ _Pre_defensive_ HQUIC Configuration,
    _In_ _Pre_defensive_ const CXPLAT_CREDENTIAL_CONFIG* CredConfig
    );

//
// Listener Context Interface.
//

typedef enum CXPLAT_LISTENER_EVENT_TYPE {
    CXPLAT_LISTENER_EVENT_NEW_CONNECTION      = 0
} CXPLAT_LISTENER_EVENT_TYPE;

typedef struct CXPLAT_LISTENER_EVENT {
    CXPLAT_LISTENER_EVENT_TYPE Type;
    union {
        struct {
            const CXPLAT_NEW_CONNECTION_INFO* Info;
            HQUIC Connection;
        } NEW_CONNECTION;
    };
} CXPLAT_LISTENER_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_LISTENER_CALLBACK)
CXPLAT_STATUS
(CXPLAT_API CXPLAT_LISTENER_CALLBACK)(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ CXPLAT_LISTENER_EVENT* Event
    );

typedef CXPLAT_LISTENER_CALLBACK *CXPLAT_LISTENER_CALLBACK_HANDLER;

//
// Opens a new listener.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_LISTENER_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ CXPLAT_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Listener, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Listener
    );

//
// Closes an existing listener. N.B. This function will deadlock if called in
// a CXPLAT_LISTENER_CALLBACK_HANDLER callback.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_API * CXPLAT_LISTENER_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Listener
    );

//
// Starts the listener processing incoming connections.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_LISTENER_START_FN)(
    _In_ _Pre_defensive_ HQUIC Listener,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const CXPLAT_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ const CXPLAT_ADDR* LocalAddress
    );

//
// Stops the listener from processing incoming connections.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_API * CXPLAT_LISTENER_STOP_FN)(
    _In_ _Pre_defensive_ HQUIC Listener
    );

//
// Connections
//

typedef enum CXPLAT_CONNECTION_EVENT_TYPE {
    CXPLAT_CONNECTION_EVENT_CONNECTED                         = 0,
    CXPLAT_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT   = 1,    // The transport started the shutdown process.
    CXPLAT_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER        = 2,    // The peer application started the shutdown process.
    CXPLAT_CONNECTION_EVENT_SHUTDOWN_COMPLETE                 = 3,    // Ready for the handle to be closed.
    CXPLAT_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED             = 4,
    CXPLAT_CONNECTION_EVENT_PEER_ADDRESS_CHANGED              = 5,
    CXPLAT_CONNECTION_EVENT_PEER_STREAM_STARTED               = 6,
    CXPLAT_CONNECTION_EVENT_STREAMS_AVAILABLE                 = 7,
    CXPLAT_CONNECTION_EVENT_PEER_NEEDS_STREAMS                = 8,
    CXPLAT_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED           = 9,
    CXPLAT_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED            = 10,
    CXPLAT_CONNECTION_EVENT_DATAGRAM_RECEIVED                 = 11,
    CXPLAT_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED       = 12,
    CXPLAT_CONNECTION_EVENT_RESUMED                           = 13,   // Server-only; provides resumption data, if any.
    CXPLAT_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED        = 14    // Client-only; provides ticket to persist, if any.
} CXPLAT_CONNECTION_EVENT_TYPE;

typedef struct CXPLAT_CONNECTION_EVENT {
    CXPLAT_CONNECTION_EVENT_TYPE Type;
    union {
        struct {
            BOOLEAN SessionResumed;
            uint8_t NegotiatedAlpnLength;
            _Field_size_(NegotiatedAlpnLength)
            const uint8_t* NegotiatedAlpn;
        } CONNECTED;
        struct {
            CXPLAT_STATUS Status;
        } SHUTDOWN_INITIATED_BY_TRANSPORT;
        struct {
            CXPLAT_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_PEER;
        struct {
            BOOLEAN HandshakeCompleted          : 1;
            BOOLEAN PeerAcknowledgedShutdown    : 1;
            BOOLEAN AppCloseInProgress          : 1;
        } SHUTDOWN_COMPLETE;
        struct {
            const CXPLAT_ADDR* Address;
        } LOCAL_ADDRESS_CHANGED;
        struct {
            const CXPLAT_ADDR* Address;
        } PEER_ADDRESS_CHANGED;
        struct {
            HQUIC Stream;
            CXPLAT_STREAM_OPEN_FLAGS Flags;
        } PEER_STREAM_STARTED;
        struct {
            uint16_t BidirectionalCount;
            uint16_t UnidirectionalCount;
        } STREAMS_AVAILABLE;
        struct {
            uint16_t IdealProcessor;
        } IDEAL_PROCESSOR_CHANGED;
        struct {
            BOOLEAN SendEnabled;
            uint16_t MaxSendLength;
        } DATAGRAM_STATE_CHANGED;
        struct {
            const CXPLAT_BUFFER* Buffer;
            CXPLAT_RECEIVE_FLAGS Flags;
        } DATAGRAM_RECEIVED;
        struct {
            /* inout */ void* ClientContext;
            CXPLAT_DATAGRAM_SEND_STATE State;
        } DATAGRAM_SEND_STATE_CHANGED;
        struct {
            uint16_t ResumptionStateLength;
            const uint8_t* ResumptionState;
        } RESUMED;
        struct {
            uint32_t ResumptionTicketLength;
            const uint8_t* ResumptionTicket;
        } RESUMPTION_TICKET_RECEIVED;
    };
} CXPLAT_CONNECTION_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_CONNECTION_CALLBACK)
CXPLAT_STATUS
(CXPLAT_API CXPLAT_CONNECTION_CALLBACK)(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ CXPLAT_CONNECTION_EVENT* Event
    );

typedef CXPLAT_CONNECTION_CALLBACK *CXPLAT_CONNECTION_CALLBACK_HANDLER;

//
// Opens a new connection.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_CONNECTION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ CXPLAT_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Connection
    );

//
// Closes an existing connection.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_API * CXPLAT_CONNECTION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Connection
    );

//
// Starts the shutdown process on the connection. This immediately and silently
// shuts down any open streams; which will trigger callbacks for
// CXPLAT_CONNECTION_EVENT_STREAM_CLOSED events. Does nothing if already shutdown.
// Can be passed either a connection or stream handle.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(CXPLAT_API * CXPLAT_CONNECTION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ CXPLAT_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ CXPLAT_UINT62 ErrorCode // Application defined error code
    );

//
// Uses the QUIC (client) handle to start a connection attempt to the
// remote server. Can be passed either a connection or stream handle.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_CONNECTION_START_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ _Pre_defensive_ HQUIC Configuration,
    _In_ CXPLAT_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(CXPLAT_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    );

//
// Sets the (server-side) configuration handle for the connection. This must be
// called on an accepted connection in order to proceed with the QUIC handshake.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_CONNECTION_SET_CONFIGURATION_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ _Pre_defensive_ HQUIC Configuration
    );

//
// Uses the QUIC (server) handle to send a resumption ticket to the remote
// client, optionally with app-specific data useful during resumption.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_CONNECTION_SEND_RESUMPTION_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ CXPLAT_SEND_RESUMPTION_FLAGS Flags,
    _In_ uint16_t DataLength,
    _In_reads_bytes_opt_(DataLength)
        const uint8_t* ResumptionData
    );

//
// Streams
//

typedef enum CXPLAT_STREAM_EVENT_TYPE {
    CXPLAT_STREAM_EVENT_START_COMPLETE            = 0,
    CXPLAT_STREAM_EVENT_RECEIVE                   = 1,
    CXPLAT_STREAM_EVENT_SEND_COMPLETE             = 2,
    CXPLAT_STREAM_EVENT_PEER_SEND_SHUTDOWN        = 3,
    CXPLAT_STREAM_EVENT_PEER_SEND_ABORTED         = 4,
    CXPLAT_STREAM_EVENT_PEER_RECEIVE_ABORTED      = 5,
    CXPLAT_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE    = 6,
    CXPLAT_STREAM_EVENT_SHUTDOWN_COMPLETE         = 7,
    CXPLAT_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE    = 8
} CXPLAT_STREAM_EVENT_TYPE;

typedef struct CXPLAT_STREAM_EVENT {
    CXPLAT_STREAM_EVENT_TYPE Type;
    union {
        struct {
            CXPLAT_STATUS Status;
            CXPLAT_UINT62 ID;
        } START_COMPLETE;
        struct {
            /* in */    uint64_t AbsoluteOffset;
            /* inout */ uint64_t TotalBufferLength;
            _Field_size_(BufferCount)
            /* in */    const CXPLAT_BUFFER* Buffers;
            _Field_range_(1, UINT32_MAX)
            /* in */    uint32_t BufferCount;
            /* in */    CXPLAT_RECEIVE_FLAGS Flags;
        } RECEIVE;
        struct {
            BOOLEAN Canceled;
            void* ClientContext;
        } SEND_COMPLETE;
        struct {
            CXPLAT_UINT62 ErrorCode;
        } PEER_SEND_ABORTED;
        struct {
            CXPLAT_UINT62 ErrorCode;
        } PEER_RECEIVE_ABORTED;
        struct {
            BOOLEAN Graceful;
        } SEND_SHUTDOWN_COMPLETE;
        struct {
            uint64_t ByteCount;
        } IDEAL_SEND_BUFFER_SIZE;
    };
} CXPLAT_STREAM_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_STREAM_CALLBACK)
CXPLAT_STATUS
(CXPLAT_API CXPLAT_STREAM_CALLBACK)(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ CXPLAT_STREAM_EVENT* Event
    );

typedef CXPLAT_STREAM_CALLBACK *CXPLAT_STREAM_CALLBACK_HANDLER;

//
// Opens a stream on the given connection.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_STREAM_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ CXPLAT_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ CXPLAT_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Stream, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Stream
    );

//
// Closes a stream handle.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_API * CXPLAT_STREAM_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Stream
    );

//
// Starts processing the stream.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_STREAM_START_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ CXPLAT_STREAM_START_FLAGS Flags
    );

//
// Shuts the stream down as specified, and waits for graceful
// shutdowns to complete. Does nothing if already shut down.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_STREAM_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ CXPLAT_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ CXPLAT_UINT62 ErrorCode // Application defined error code
    );

//
// Sends data on an open stream.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_STREAM_SEND_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_reads_(BufferCount) _Pre_defensive_
        const CXPLAT_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ CXPLAT_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );

//
// Completes a previously pended receive callback.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_STREAM_RECEIVE_COMPLETE_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ uint64_t BufferLength
    );

//
// Enables or disables stream receive callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_STREAM_RECEIVE_SET_ENABLED_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ BOOLEAN IsEnabled
    );

//
// Datagrams
//

//
// Sends an unreliable datagram on the connection. Note, the total payload
// of the send must fit in a single QUIC packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
(CXPLAT_API * CXPLAT_DATAGRAM_SEND_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_reads_(BufferCount) _Pre_defensive_
        const CXPLAT_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ CXPLAT_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );

//
// API Function Table.
//
typedef struct CXPLAT_API_TABLE {

    CXPLAT_SET_CONTEXT_FN                 SetContext;
    CXPLAT_GET_CONTEXT_FN                 GetContext;
    CXPLAT_SET_CALLBACK_HANDLER_FN        SetCallbackHandler;

    CXPLAT_SET_PARAM_FN                   SetParam;
    CXPLAT_GET_PARAM_FN                   GetParam;

    CXPLAT_REGISTRATION_OPEN_FN           RegistrationOpen;
    CXPLAT_REGISTRATION_CLOSE_FN          RegistrationClose;
    CXPLAT_REGISTRATION_SHUTDOWN_FN       RegistrationShutdown;

    CXPLAT_CONFIGURATION_OPEN_FN          ConfigurationOpen;
    CXPLAT_CONFIGURATION_CLOSE_FN         ConfigurationClose;
    CXPLAT_CONFIGURATION_LOAD_CREDENTIAL_FN
                                        ConfigurationLoadCredential;

    CXPLAT_LISTENER_OPEN_FN               ListenerOpen;
    CXPLAT_LISTENER_CLOSE_FN              ListenerClose;
    CXPLAT_LISTENER_START_FN              ListenerStart;
    CXPLAT_LISTENER_STOP_FN               ListenerStop;

    CXPLAT_CONNECTION_OPEN_FN             ConnectionOpen;
    CXPLAT_CONNECTION_CLOSE_FN            ConnectionClose;
    CXPLAT_CONNECTION_SHUTDOWN_FN         ConnectionShutdown;
    CXPLAT_CONNECTION_START_FN            ConnectionStart;
    CXPLAT_CONNECTION_SET_CONFIGURATION_FN
                                        ConnectionSetConfiguration;
    CXPLAT_CONNECTION_SEND_RESUMPTION_FN  ConnectionSendResumptionTicket;

    CXPLAT_STREAM_OPEN_FN                 StreamOpen;
    CXPLAT_STREAM_CLOSE_FN                StreamClose;
    CXPLAT_STREAM_START_FN                StreamStart;
    CXPLAT_STREAM_SHUTDOWN_FN             StreamShutdown;
    CXPLAT_STREAM_SEND_FN                 StreamSend;
    CXPLAT_STREAM_RECEIVE_COMPLETE_FN     StreamReceiveComplete;
    CXPLAT_STREAM_RECEIVE_SET_ENABLED_FN  StreamReceiveSetEnabled;

    CXPLAT_DATAGRAM_SEND_FN               DatagramSend;

} CXPLAT_API_TABLE;

//
// Opens the API library and initializes it if this is the first call for the
// process. It returns API function table for the rest of the API's functions.
// CxPlatClose must be called when the app is done with the function table.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
CXPLAT_API
CxPlatOpen(
    _Out_ _Pre_defensive_ const CXPLAT_API_TABLE** QuicApi
    );

//
// Cleans up the function table returned from CxPlatOpen and releases the
// reference on the API.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CXPLAT_API
CxPlatClose(
    _In_ _Pre_defensive_ const CXPLAT_API_TABLE* QuicApi
    );

#if defined(__cplusplus)
}
#endif

#endif // _MSCXPLAT_
