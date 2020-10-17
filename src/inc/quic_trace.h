/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic defines two classes of tracing:

    Events      These are well-defined and have explicit formats. Each event is
                defined with its own, unique function. These are generally used
                for automated log processing (quicetw for instance).

    Logs        These use a printf style format for generally tracing more
                detailed information than Events, and are purely for human
                consumption.

    Each class is individually configurable at compile time. Different platforms
    or build configurations can have their own desired behavior. The following
    configuration options are currently supported:

    CXPLAT_EVENTS_STUB            No-op all Events
    CXPLAT_EVENTS_MANIFEST_ETW    Write to Windows ETW framework

    CXPLAT_LOGS_STUB              No-op all Logs
    CXPLAT_LOGS_MANIFEST_ETW      Write to Windows ETW framework

    CXPLAT_CLOG                   Bypasses these mechanisms and uses CLOG to generate logging

 --*/

#pragma once

#if !defined(CXPLAT_CLOG)
#if !defined(CXPLAT_EVENTS_STUB) && !defined(CXPLAT_EVENTS_MANIFEST_ETW)
#error "Must define one CXPLAT_EVENTS_*"
#endif

#if !defined(CXPLAT_LOGS_STUB) && !defined(CXPLAT_LOGS_MANIFEST_ETW)
#error "Must define one CXPLAT_LOGS_*"
#endif
#endif

typedef enum CXPLAT_FLOW_BLOCK_REASON {
    CXPLAT_FLOW_BLOCKED_SCHEDULING            = 0x01,
    CXPLAT_FLOW_BLOCKED_PACING                = 0x02,
    CXPLAT_FLOW_BLOCKED_AMPLIFICATION_PROT    = 0x04,
    CXPLAT_FLOW_BLOCKED_CONGESTION_CONTROL    = 0x08,
    CXPLAT_FLOW_BLOCKED_CONN_FLOW_CONTROL     = 0x10,
    CXPLAT_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL= 0x20,
    CXPLAT_FLOW_BLOCKED_STREAM_FLOW_CONTROL   = 0x40,
    CXPLAT_FLOW_BLOCKED_APP                   = 0x80
} CXPLAT_FLOW_BLOCK_REASON;

typedef enum CXPLAT_TRACE_PACKET_TYPE {
    CXPLAT_TRACE_PACKET_VN,
    CXPLAT_TRACE_PACKET_INITIAL,
    CXPLAT_TRACE_PACKET_ZERO_RTT,
    CXPLAT_TRACE_PACKET_HANDSHAKE,
    CXPLAT_TRACE_PACKET_RETRY,
    CXPLAT_TRACE_PACKET_ONE_RTT
} CXPLAT_TRACE_PACKET_TYPE;

typedef enum CXPLAT_TRACE_PACKET_LOSS_REASON {
    CXPLAT_TRACE_PACKET_LOSS_RACK,
    CXPLAT_TRACE_PACKET_LOSS_FACK,
    CXPLAT_TRACE_PACKET_LOSS_PROBE
} CXPLAT_TRACE_PACKET_LOSS_REASON;

typedef enum CXPLAT_TRACE_API_TYPE {
    CXPLAT_TRACE_API_SET_PARAM,
    CXPLAT_TRACE_API_GET_PARAM,
    CXPLAT_TRACE_API_REGISTRATION_OPEN,
    CXPLAT_TRACE_API_REGISTRATION_CLOSE,
    CXPLAT_TRACE_API_REGISTRATION_SHUTDOWN,
    CXPLAT_TRACE_API_CONFIGURATION_OPEN,
    CXPLAT_TRACE_API_CONFIGURATION_CLOSE,
    CXPLAT_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
    CXPLAT_TRACE_API_LISTENER_OPEN,
    CXPLAT_TRACE_API_LISTENER_CLOSE,
    CXPLAT_TRACE_API_LISTENER_START,
    CXPLAT_TRACE_API_LISTENER_STOP,
    CXPLAT_TRACE_API_CONNECTION_OPEN,
    CXPLAT_TRACE_API_CONNECTION_CLOSE,
    CXPLAT_TRACE_API_CONNECTION_SHUTDOWN,
    CXPLAT_TRACE_API_CONNECTION_START,
    CXPLAT_TRACE_API_CONNECTION_SET_CONFIGURATION,
    CXPLAT_TRACE_API_CONNECTION_SEND_RESUMPTION_TICKET,
    CXPLAT_TRACE_API_STREAM_OPEN,
    CXPLAT_TRACE_API_STREAM_CLOSE,
    CXPLAT_TRACE_API_STREAM_START,
    CXPLAT_TRACE_API_STREAM_SHUTDOWN,
    CXPLAT_TRACE_API_STREAM_SEND,
    CXPLAT_TRACE_API_STREAM_RECEIVE_COMPLETE,
    CXPLAT_TRACE_API_STREAM_RECEIVE_SET_ENABLED,
    CXPLAT_TRACE_API_DATAGRAM_SEND,
    CXPLAT_TRACE_API_COUNT // Must be last
} CXPLAT_TRACE_API_TYPE;

typedef enum CXPLAT_TRACE_LEVEL {
    CXPLAT_TRACE_LEVEL_DEV,
    CXPLAT_TRACE_LEVEL_VERBOSE,
    CXPLAT_TRACE_LEVEL_INFO,
    CXPLAT_TRACE_LEVEL_WARNING,
    CXPLAT_TRACE_LEVEL_ERROR,
    CXPLAT_TRACE_LEVEL_PACKET_VERBOSE,
    CXPLAT_TRACE_LEVEL_PACKET_INFO,
    CXPLAT_TRACE_LEVEL_PACKET_WARNING
} CXPLAT_TRACE_LEVEL;

//
// Called from the platform code to trigger a tracing rundown for all objects
// in the current process (or kernel mode).
//
#ifdef __cplusplus
extern "C"
#endif
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTraceRundown(
    void
    );

#ifdef CXPLAT_CLOG

#define QuicTraceLogStreamVerboseEnabled() TRUE
#define QuicTraceLogErrorEnabled()   TRUE
#define QuicTraceLogWarningEnabled() TRUE
#define QuicTraceLogInfoEnabled()    TRUE
#define QuicTraceLogVerboseEnabled() TRUE
#define QuicTraceEventEnabled(x) TRUE

#else

#ifdef CXPLAT_EVENTS_STUB

#define QuicTraceEventEnabled(Name) FALSE
#define QuicTraceEvent(Name, Fmt, ...)

#define CLOG_BYTEARRAY(Len, Data)

#endif // CXPLAT_EVENTS_STUB

#ifdef CXPLAT_EVENTS_MANIFEST_ETW

#include <evntprov.h>

#ifdef __cplusplus
extern "C"
#endif
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_same_
void
NTAPI
QuicEtwCallback(
    _In_ LPCGUID SourceId,
    _In_ ULONG ControlCode,
    _In_ UCHAR Level,
    _In_ ULONGLONG MatchAnyKeyword,
    _In_ ULONGLONG MatchAllKeyword,
    _In_opt_ PEVENT_FILTER_DESCRIPTOR FilterData,
    _Inout_opt_ PVOID CallbackContext
    );

//
// Defining MCGEN_PRIVATE_ENABLE_CALLBACK_V2, makes McGenControlCallbackV2
// call our user-defined callback routine. See MsQuicEvents.h.
//
#define MCGEN_PRIVATE_ENABLE_CALLBACK_V2 QuicEtwCallback

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#pragma warning(pop)

#define QuicTraceEventEnabled(Name) EventEnabledQuic##Name()
#define _QuicTraceEvent(Name, Args) EventWriteQuic##Name##Args
#define QuicTraceEvent(Name, Fmt, ...) _QuicTraceEvent(Name, (__VA_ARGS__))

#define CLOG_BYTEARRAY(Len, Data) (uint8_t)(Len), (uint8_t*)(Data)

#endif // CXPLAT_EVENTS_MANIFEST_ETW

#ifdef CXPLAT_LOGS_STUB

#define QuicTraceLogErrorEnabled()   FALSE
#define QuicTraceLogWarningEnabled() FALSE
#define QuicTraceLogInfoEnabled()    FALSE
#define QuicTraceLogVerboseEnabled() FALSE

inline
void
QuicTraceStubVarArgs(
    _In_ const void* Fmt,
    ...
    )
{
    UNREFERENCED_PARAMETER(Fmt);
}

#define QuicTraceLogError(X,...)            QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogWarning(X,...)          QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogInfo(X,...)             QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogVerbose(X,...)          QuicTraceStubVarArgs(__VA_ARGS__)

#define QuicTraceLogConnError(X,...)        QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogConnWarning(X,...)      QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogConnInfo(X,...)         QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogConnVerbose(X,...)      QuicTraceStubVarArgs(__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() FALSE

#define QuicTraceLogStreamError(X,...)      QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogStreamWarning(X,...)    QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogStreamInfo(X,...)       QuicTraceStubVarArgs(__VA_ARGS__)
#define QuicTraceLogStreamVerbose(X,...)    QuicTraceStubVarArgs(__VA_ARGS__)

#endif // CXPLAT_LOGS_STUB

#ifdef CXPLAT_LOGS_MANIFEST_ETW

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "MsQuicEtw.h"
#pragma warning(pop)

#include <stdio.h>

#define QuicTraceLogErrorEnabled()   EventEnabledQuicLogError()
#define QuicTraceLogWarningEnabled() EventEnabledQuicLogWarning()
#define QuicTraceLogInfoEnabled()    EventEnabledQuicLogInfo()
#define QuicTraceLogVerboseEnabled() EventEnabledQuicLogVerbose()

#define CXPLAT_ETW_BUFFER_LENGTH 128

#define LogEtw(EventName, Fmt, ...) \
    if (EventEnabledQuicLog##EventName()) { \
        char EtwBuffer[CXPLAT_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteQuicLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogEtwType(Type, EventName, Ptr, Fmt, ...) \
    if (EventEnabledQuic##Type##Log##EventName()) { \
        char EtwBuffer[CXPLAT_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteQuic##Type##Log##EventName##_AssumeEnabled(Ptr, EtwBuffer); \
    }

#define QuicTraceLogError(Name, Fmt, ...)               LogEtw(Error, Fmt, ##__VA_ARGS__)
#define QuicTraceLogWarning(Name, Fmt, ...)             LogEtw(Warning, Fmt, ##__VA_ARGS__)
#define QuicTraceLogInfo(Name, Fmt, ...)                LogEtw(Info, Fmt, ##__VA_ARGS__)
#define QuicTraceLogVerbose(Name, Fmt, ...)             LogEtw(Verbose, Fmt, ##__VA_ARGS__)

#define QuicTraceLogConnError(Name, Ptr, Fmt, ...)      LogEtwType(Conn, Error, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnWarning(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnInfo(Name, Ptr, Fmt, ...)       LogEtwType(Conn, Info, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogConnVerbose(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#define QuicTraceLogStreamVerboseEnabled() EventEnabledQuicStreamLogVerbose()

#define QuicTraceLogStreamError(Name, Ptr, Fmt, ...)    LogEtwType(Stream, Error, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamWarning(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamInfo(Name, Ptr, Fmt, ...)     LogEtwType(Stream, Info, Ptr, Fmt, ##__VA_ARGS__)
#define QuicTraceLogStreamVerbose(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#endif // CXPLAT_LOGS_MANIFEST_ETW

#endif // CXPLAT_CLOG
