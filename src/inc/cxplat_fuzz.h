/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file defines an interface to cxplat_fuzz which can be used in place
    of cxplat to create quic clients or servers. This is an addon which
    exposes hooks into send, receive, and encrypt operations performed by
    the quic library.

    These hooks can be used to create a fuzzer capable of injecting
    payloads into QUIC connections, while still using core library to
    create semantically valid sessions.

    cxplat_fuzz also provides a mode of operation which disables the
    use of os-level sockets, and instead provides a "Simulated Receive"
    function, allowing for fuzzers to target and use cxplat without
    the need to create unique socket bindings for each quic connection.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#define CXPLAT_FUZZ_BUFFER_MAX 0x1000

//
// Callback to be registered and called each time cxplat sends a packet.
// In 'Simulated' mode this used to capture the data which would be sent
// via OS sockets.
//
typedef
void
(*CXPLAT_FUZZ_SEND_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _Inout_updates_bytes_(Length) uint8_t *Buffer,
    _In_ DWORD Length
    );

//
// Callback to be registered and called each time cxplat receives a packet.
// In 'Simulated' mode this is still called.
//
typedef
void
(*CXPLAT_FUZZ_RECV_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _Inout_updates_bytes_(Length) uint8_t *Buffer,
    _In_ DWORD Length
    );

//
// Callback to be registered and called just prior to cxplat encrypting
// a payload. This function may modify or entirely replace the
// datagram's data.
//
typedef
void
(*CXPLAT_FUZZ_INJECT_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _In_ uint8_t *OriginalBuffer,
    _In_ uint32_t OriginalBufferLength,
    _In_ uint16_t HeaderLength,
    _Out_ uint8_t ** NewBuffer,
    _Out_ uint16_t *NewLength
    );

//
// Callback to be registered and called prior to cxplat encrypting
// a payload. Can be used to capture or modify valid QUIC payloads.
//
typedef
void
(*CXPLAT_FUZZ_ENCRYPT_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _Inout_updates_bytes_(Length) uint8_t* Buffer,
    _In_ DWORD Length
    );

//
// An internal global structure used to track fuzzer configuration
// and state exposed via cxplat_fuzz.
//
typedef struct CXPLAT_FUZZ_CONTEXT {
    CXPLAT_FUZZ_SEND_CALLBACK_FN SendCallback;
    CXPLAT_FUZZ_RECV_CALLBACK_FN RecvCallback;
    CXPLAT_FUZZ_INJECT_CALLBACK_FN InjectCallback;
    CXPLAT_FUZZ_ENCRYPT_CALLBACK_FN EncryptCallback;
    uint8_t RedirectDataPath;
    void *CallbackContext;
    //
    // When in 'simulate' mode, is set to the last-used connection's socket
    // structure.
    //
    void *Socket;
    void *RealSendMsg;
    void *RealRecvMsg;
} CXPLAT_FUZZ_CONTEXT;

extern CXPLAT_FUZZ_CONTEXT CxPlatFuzzerContext;

//
// Function to enable fuzzing functionality in cxplat_fuzz.
//
// CallbackContext is a pointer to an opaque structure that will be
// passed to all callbacks.
//
// Passing a non-zero value as RedirectDataPath will disable
// cxplat_fuzz's use of OS sockets, and assume that the consuming
// application will make calls to CxPlatSimulateReceive.
//
void
CxPlatFuzzInit(
    _Inout_ void *CallbackContext,
    _In_ uint8_t RedirectDataPath
    );

//
// Sets callback to be invoked each time cxplat_fuzz sends a datagram.
//
void
CxPlatFuzzRegisterSendCallback(
    _In_ CXPLAT_FUZZ_SEND_CALLBACK_FN Callback
    );

//
// Sets callback to be invoked each time cxplat_fuzz receives a datagram.
//
void
CxPlatFuzzRegisterRecvCallback(
    _In_ CXPLAT_FUZZ_RECV_CALLBACK_FN Callback
    );

//
// Sets callback to be invoked each time cxplat_fuzz creates a new datagram.
// to be sent.
//
void
CxPlatFuzzRegisterInjectCallback(
    _In_ CXPLAT_FUZZ_INJECT_CALLBACK_FN Callback
    );

//
// Sets callback to be invoked each time cxplat_fuzz encrypts a datagram.
//
void
CxPlatFuzzRegisterEncryptCallback(
    _In_ CXPLAT_FUZZ_ENCRYPT_CALLBACK_FN Callback
    );

//
// When operating in 'Simulate' mode, can be called to deliver a datagram.
// to the last-used connection in an cxplat_fuzz session.
//
void
CxPlatFuzzSimulateReceive(
    _In_ const CXPLAT_ADDR *SourceAddress,
    _In_reads_(PacketLength) uint8_t *PacketData,
    _In_ uint16_t PacketLength
    );

#if defined(__cplusplus)
}
#endif
