/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    CxPlat defines two classes of tracing:

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
CxPlatTraceRundown(
    void
    );

#ifdef CXPLAT_CLOG

#define CxPlatTraceLogStreamVerboseEnabled() TRUE
#define CxPlatTraceLogErrorEnabled()   TRUE
#define CxPlatTraceLogWarningEnabled() TRUE
#define CxPlatTraceLogInfoEnabled()    TRUE
#define CxPlatTraceLogVerboseEnabled() TRUE
#define CxPlatTraceEventEnabled(x) TRUE

#else

#ifdef CXPLAT_EVENTS_STUB

#define CxPlatTraceEventEnabled(Name) FALSE
#define CxPlatTraceEvent(Name, Fmt, ...)

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
CxPlatEtwCallback(
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
// call our user-defined callback routine. See CxPlatEvents.h.
//
#define MCGEN_PRIVATE_ENABLE_CALLBACK_V2 CxPlatEtwCallback

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "CxPlatEtw.h"
#pragma warning(pop)

#define CxPlatTraceEventEnabled(Name) EventEnabledCxPlat##Name()
#define _CxPlatTraceEvent(Name, Args) EventWriteCxPlat##Name##Args
#define CxPlatTraceEvent(Name, Fmt, ...) _CxPlatTraceEvent(Name, (__VA_ARGS__))

#define CLOG_BYTEARRAY(Len, Data) (uint8_t)(Len), (uint8_t*)(Data)

#endif // CXPLAT_EVENTS_MANIFEST_ETW

#ifdef CXPLAT_LOGS_STUB

#define CxPlatTraceLogErrorEnabled()   FALSE
#define CxPlatTraceLogWarningEnabled() FALSE
#define CxPlatTraceLogInfoEnabled()    FALSE
#define CxPlatTraceLogVerboseEnabled() FALSE

inline
void
CxPlatTraceStubVarArgs(
    _In_ const void* Fmt,
    ...
    )
{
    UNREFERENCED_PARAMETER(Fmt);
}

#define CxPlatTraceLogError(X,...)            CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogWarning(X,...)          CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogInfo(X,...)             CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogVerbose(X,...)          CxPlatTraceStubVarArgs(__VA_ARGS__)

#define CxPlatTraceLogConnError(X,...)        CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogConnWarning(X,...)      CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogConnInfo(X,...)         CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogConnVerbose(X,...)      CxPlatTraceStubVarArgs(__VA_ARGS__)

#define CxPlatTraceLogStreamVerboseEnabled() FALSE

#define CxPlatTraceLogStreamError(X,...)      CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogStreamWarning(X,...)    CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogStreamInfo(X,...)       CxPlatTraceStubVarArgs(__VA_ARGS__)
#define CxPlatTraceLogStreamVerbose(X,...)    CxPlatTraceStubVarArgs(__VA_ARGS__)

#endif // CXPLAT_LOGS_STUB

#ifdef CXPLAT_LOGS_MANIFEST_ETW

#pragma warning(push) // Don't care about warnings from generated files
#pragma warning(disable:6001)
#pragma warning(disable:26451)
#include "CxPlatEtw.h"
#pragma warning(pop)

#include <stdio.h>

#define CxPlatTraceLogErrorEnabled()   EventEnabledCxPlatLogError()
#define CxPlatTraceLogWarningEnabled() EventEnabledCxPlatLogWarning()
#define CxPlatTraceLogInfoEnabled()    EventEnabledCxPlatLogInfo()
#define CxPlatTraceLogVerboseEnabled() EventEnabledCxPlatLogVerbose()

#define CXPLAT_ETW_BUFFER_LENGTH 128

#define LogEtw(EventName, Fmt, ...) \
    if (EventEnabledCxPlatLog##EventName()) { \
        char EtwBuffer[CXPLAT_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteCxPlatLog##EventName##_AssumeEnabled(EtwBuffer); \
    }

#define LogEtwType(Type, EventName, Ptr, Fmt, ...) \
    if (EventEnabledCxPlat##Type##Log##EventName()) { \
        char EtwBuffer[CXPLAT_ETW_BUFFER_LENGTH]; \
        _snprintf_s(EtwBuffer, sizeof(EtwBuffer), _TRUNCATE, Fmt, ##__VA_ARGS__); \
        EventWriteCxPlat##Type##Log##EventName##_AssumeEnabled(Ptr, EtwBuffer); \
    }

#define CxPlatTraceLogError(Name, Fmt, ...)               LogEtw(Error, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogWarning(Name, Fmt, ...)             LogEtw(Warning, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogInfo(Name, Fmt, ...)                LogEtw(Info, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogVerbose(Name, Fmt, ...)             LogEtw(Verbose, Fmt, ##__VA_ARGS__)

#define CxPlatTraceLogConnError(Name, Ptr, Fmt, ...)      LogEtwType(Conn, Error, Ptr, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogConnWarning(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogConnInfo(Name, Ptr, Fmt, ...)       LogEtwType(Conn, Info, Ptr, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogConnVerbose(Name, Ptr, Fmt, ...)    LogEtwType(Conn, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#define CxPlatTraceLogStreamVerboseEnabled() EventEnabledCxPlatStreamLogVerbose()

#define CxPlatTraceLogStreamError(Name, Ptr, Fmt, ...)    LogEtwType(Stream, Error, Ptr, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogStreamWarning(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Warning, Ptr, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogStreamInfo(Name, Ptr, Fmt, ...)     LogEtwType(Stream, Info, Ptr, Fmt, ##__VA_ARGS__)
#define CxPlatTraceLogStreamVerbose(Name, Ptr, Fmt, ...)  LogEtwType(Stream, Verbose, Ptr, Fmt, ##__VA_ARGS__)

#endif // CXPLAT_LOGS_MANIFEST_ETW

#endif // CXPLAT_CLOG
