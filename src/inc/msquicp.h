/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Private definitions for MsQuic.

--*/

#pragma once

#ifndef _MSQUICP_
#define _MSQUICP_

#include <msquic.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_RECV_DATAGRAM CXPLAT_RECV_DATAGRAM;
typedef struct CXPLAT_DATAPATH_SEND_CONTEXT CXPLAT_DATAPATH_SEND_CONTEXT;

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
(CXPLAT_API * CXPLAT_TEST_DATAPATH_RECEIVE_HOOK)(
    _Inout_ CXPLAT_RECV_DATAGRAM* Datagram
    );

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(CXPLAT_API * CXPLAT_TEST_DATAPATH_SEND_HOOK)(
    _Inout_ CXPLAT_ADDR* RemoteAddress,
    _Inout_opt_ CXPLAT_ADDR* LocalAddress,
    _Inout_ CXPLAT_DATAPATH_SEND_CONTEXT* SendContext
    );

typedef struct CXPLAT_TEST_DATAPATH_HOOKS {
    CXPLAT_TEST_DATAPATH_RECEIVE_HOOK Receive;
    CXPLAT_TEST_DATAPATH_SEND_HOOK Send;
} CXPLAT_TEST_DATAPATH_HOOKS;

#if DEBUG
//
// Datapath hooks are currently only enabled on debug builds for functional
// testing helpers.
//
#define CXPLAT_TEST_DATAPATH_HOOKS_ENABLED 1
#endif

typedef struct CXPLAT_PRIVATE_TRANSPORT_PARAMETER {
    uint16_t Type;
    uint16_t Length;
    _Field_size_(Length)
    const uint8_t* Buffer;
} CXPLAT_PRIVATE_TRANSPORT_PARAMETER;

//
// The different private parameters for CXPLAT_PARAM_LEVEL_GLOBAL.
//

#define CXPLAT_PARAM_GLOBAL_TEST_DATAPATH_HOOKS           0x80000001  // CXPLAT_TEST_DATAPATH_HOOKS*

//
// The different private parameters for CXPLAT_PARAM_LEVEL_CONNECTION.
//

#define CXPLAT_PARAM_CONN_FORCE_KEY_UPDATE                0x80000001  // No payload
#define CXPLAT_PARAM_CONN_FORCE_CID_UPDATE                0x80000002  // No payload
#define CXPLAT_PARAM_CONN_TEST_TRANSPORT_PARAMETER        0x80000003  // CXPLAT_PRIVATE_TRANSPORT_PARAMETER

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
