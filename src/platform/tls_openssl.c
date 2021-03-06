/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling OpenSSL.

--*/

#include "platform_internal.h"

#define OPENSSL_SUPPRESS_DEPRECATED 1 // For hmac.h, which was deprecated in 3.0
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/hmac.h"
#ifdef CXPLAT_CLOG
#include "tls_openssl.c.clog.h"
#endif

uint16_t CxPlatTlsTPHeaderSize = 0;

//
// The QUIC sec config object. Created once per listener on server side and
// once per connection on client side.
//

typedef struct CXPLAT_SEC_CONFIG {

    //
    // The SSL context associated with the sec config.
    //

    SSL_CTX *SSLCtx;

} CXPLAT_SEC_CONFIG;

//
// A TLS context associated per connection.
//

typedef struct CXPLAT_TLS {

    //
    // The TLS configuration information and credentials.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // Indicates if this context belongs to server side or client side
    // connection.
    //
    BOOLEAN IsServer;

    //
    // The ALPN buffer.
    //
    uint16_t AlpnBufferLength;
    const uint8_t* AlpnBuffer;

    //
    // On client side stores a NULL terminated SNI.
    //
    const char* SNI;

    //
    // Ssl - A SSL object associated with the connection.
    //
    SSL *Ssl;

    //
    // State - The TLS state associated with the connection.
    // ResultFlags - Stores the result of the TLS data processing operation.
    //

    CXPLAT_TLS_PROCESS_STATE* State;
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    //
    // Callback context and handler for QUIC TP.
    //
    CXPLAT_CONNECTION* Connection;
    CXPLAT_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;

} CXPLAT_TLS;

//
// Default list of Cipher used.
//
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS    "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"

//
// Default list of curves for ECDHE ciphers.
//
#define CXPLAT_TLS_DEFAULT_SSL_CURVES     "P-256:X25519:P-384:P-521"

//
// Default cert verify depth.
//
#define CXPLAT_TLS_DEFAULT_VERIFY_DEPTH  10

//
// Hack to set trusted cert file on client side.
//
char *CxPlatOpenSslClientTrustedCert = NULL;

CXPLAT_STATUS
CxPlatTlsLibraryInitialize(
    void
    )
{
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "OPENSSL_init_ssl failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    //
    // OPENSSL_init_ssl() may leave errors in the error queue while returning
    // success.
    //

    ERR_clear_error();

    //
    // LINUX_TODO:Add Check for openssl library QUIC support.
    //

    return CXPLAT_STATUS_SUCCESS;
}

void
CxPlatTlsLibraryUninitialize(
    void
    )
{
}

static
int
CxPlatTlsAlpnSelectCallback(
    _In_ SSL *Ssl,
    _Out_writes_bytes_(Outlen) const unsigned char **Out,
    _Out_ unsigned char *OutLen,
    _In_reads_bytes_(Inlen) const unsigned char *In,
    _In_ unsigned int InLen,
    _In_ void *Arg
    )
{
    UNREFERENCED_PARAMETER(In);
    UNREFERENCED_PARAMETER(InLen);
    UNREFERENCED_PARAMETER(Arg);

    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    //
    // QUIC already parsed and picked the ALPN to use and set it in the
    // NegotiatedAlpn variable.
    //

    CXPLAT_DBG_ASSERT(TlsContext->State->NegotiatedAlpn != NULL);
    *OutLen = TlsContext->State->NegotiatedAlpn[0];
    *Out = TlsContext->State->NegotiatedAlpn + 1;

    return SSL_TLSEXT_ERR_OK;
}

CXPLAT_STATIC_ASSERT((int)ssl_encryption_initial == (int)CXPLAT_PACKET_KEY_INITIAL, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)ssl_encryption_early_data == (int)CXPLAT_PACKET_KEY_0_RTT, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)ssl_encryption_handshake == (int)CXPLAT_PACKET_KEY_HANDSHAKE, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)ssl_encryption_application == (int)CXPLAT_PACKET_KEY_1_RTT, "Code assumes exact match!");

void
CxPlatTlsNegotiatedCiphers(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ CXPLAT_AEAD_TYPE *AeadType,
    _Out_ CXPLAT_HASH_TYPE *HashType
    )
{
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(TlsContext->Ssl))) {
    case 0x03001301u: // TLS_AES_128_GCM_SHA256
        *AeadType = CXPLAT_AEAD_AES_128_GCM;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    case 0x03001302u: // TLS_AES_256_GCM_SHA384
        *AeadType = CXPLAT_AEAD_AES_256_GCM;
        *HashType = CXPLAT_HASH_SHA384;
        break;
    case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
        *AeadType = CXPLAT_AEAD_CHACHA20_POLY1305;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
    }
}

int
CxPlatTlsSetEncryptionSecretsCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(SecretLen) const uint8_t* ReadSecret,
    _In_reads_(SecretLen) const uint8_t* WriteSecret,
    _In_ size_t SecretLen
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;
    CXPLAT_PACKET_KEY_TYPE KeyType = (CXPLAT_PACKET_KEY_TYPE)Level;
    CXPLAT_STATUS Status;

    CxPlatTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        Level);

    CXPLAT_SECRET Secret;
    CxPlatTlsNegotiatedCiphers(TlsContext, &Secret.Aead, &Secret.Hash);
    CxPlatCopyMemory(Secret.Secret, WriteSecret, SecretLen);

    CXPLAT_DBG_ASSERT(TlsState->WriteKeys[KeyType] == NULL);
    Status =
        CxPlatPacketKeyDerive(
            KeyType,
            &Secret,
            "write secret",
            TRUE,
            &TlsState->WriteKeys[KeyType]);
    if (CXPLAT_FAILED(Status)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    TlsState->WriteKey = KeyType;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
    CxPlatCopyMemory(Secret.Secret, ReadSecret, SecretLen);

    CXPLAT_DBG_ASSERT(TlsState->ReadKeys[KeyType] == NULL);
    Status =
        CxPlatPacketKeyDerive(
            KeyType,
            &Secret,
            "read secret",
            TRUE,
            &TlsState->ReadKeys[KeyType]);
    if (CXPLAT_FAILED(Status)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    if (TlsContext->IsServer && KeyType == CXPLAT_PACKET_KEY_1_RTT) {
        //
        // The 1-RTT read keys aren't actually allowed to be used until the
        // handshake completes.
        //
    } else {
        TlsState->ReadKey = KeyType;
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
    }

    return 1;
}

int
CxPlatTlsAddHandshakeDataCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(Length) const uint8_t *Data,
    _In_ size_t Length
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;

    CXPLAT_PACKET_KEY_TYPE KeyType = (CXPLAT_PACKET_KEY_TYPE)Level;
    CXPLAT_DBG_ASSERT(KeyType == 0 || TlsState->WriteKeys[KeyType] != NULL);

    CxPlatTraceLogConnVerbose(
        OpenSslAddHandshakeData,
        TlsContext->Connection,
        "Sending %llu handshake bytes (Level = %u)",
        Length,
        Level);

    if (Length + TlsState->BufferLength > 0xF000) {
        CxPlatTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Too much handshake data");
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    if (Length + TlsState->BufferLength > (size_t)TlsState->BufferAllocLength) {
        //
        // Double the allocated buffer length until there's enough room for the
        // new data.
        //
        uint16_t NewBufferAllocLength = TlsState->BufferAllocLength;
        while (Length + TlsState->BufferLength > (size_t)NewBufferAllocLength) {
            NewBufferAllocLength <<= 1;
        }

        uint8_t* NewBuffer = CXPLAT_ALLOC_NONPAGED(NewBufferAllocLength);
        if (NewBuffer == NULL) {
            CxPlatTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto buffer",
                NewBufferAllocLength);
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        CxPlatCopyMemory(
            NewBuffer,
            TlsState->Buffer,
            TlsState->BufferLength);
        CXPLAT_FREE(TlsState->Buffer);
        TlsState->Buffer = NewBuffer;
        TlsState->BufferAllocLength = NewBufferAllocLength;
    }

    switch (KeyType) {
    case CXPLAT_PACKET_KEY_HANDSHAKE:
        if (TlsState->BufferOffsetHandshake == 0) {
            TlsState->BufferOffsetHandshake = TlsState->BufferTotalLength;
            CxPlatTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                TlsState->BufferOffsetHandshake);
        }
        break;
    case CXPLAT_PACKET_KEY_1_RTT:
        if (TlsState->BufferOffset1Rtt == 0) {
            TlsState->BufferOffset1Rtt = TlsState->BufferTotalLength;
            CxPlatTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                TlsState->BufferOffset1Rtt);
        }
        break;
    default:
        break;
    }

    CxPlatCopyMemory(
        TlsState->Buffer + TlsState->BufferLength,
        Data,
        Length);
    TlsState->BufferLength += (uint16_t)Length;
    TlsState->BufferTotalLength += (uint16_t)Length;

    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_DATA;

    return 1;
}

int
CxPlatTlsFlushFlightCallback(
    _In_ SSL *Ssl
    )
{
    UNREFERENCED_PARAMETER(Ssl);
    return 1;
}

int
CxPlatTlsSendAlertCallback(
    _In_ SSL *Ssl,
    _In_ enum ssl_encryption_level_t Level,
    _In_ uint8_t Alert
    )
{
    UNREFERENCED_PARAMETER(Level);

    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    CxPlatTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        Level);

    TlsContext->State->AlertCode = Alert;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;

    return 1;
}

int
CxPlatTlsClientHelloCallback(
    _In_ SSL *Ssl,
    _Out_opt_ int *Alert,
    _In_ void *arg
    )
{
    UNREFERENCED_PARAMETER(arg);
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    const uint8_t* TransportParams;
    size_t TransportParamLen;

    if (!SSL_client_hello_get0_ext(
            Ssl,
            TLS_EXTENSION_TYPE_CXPLAT_TRANSPORT_PARAMETERS,
            &TransportParams,
            &TransportParamLen)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        *Alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    if (!TlsContext->ReceiveTPCallback(
            TlsContext->Connection,
            (uint16_t)TransportParamLen,
            TransportParams)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

SSL_CXPLAT_METHOD OpenSslCxPlatCallbacks = {
    CxPlatTlsSetEncryptionSecretsCallback,
    CxPlatTlsAddHandshakeDataCallback,
    CxPlatTlsFlushFlightCallback,
    CxPlatTlsSendAlertCallback
};

CXPLAT_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const CXPLAT_CREDENTIAL_CONFIG* CredConfig,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    if (CredConfig->Flags & CXPLAT_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return CXPLAT_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Flags & CXPLAT_CREDENTIAL_FLAG_ENABLE_OCSP) {
        return CXPLAT_STATUS_NOT_SUPPORTED; // Not supported by this TLS implementation
    }

    if (CredConfig->TicketKey != NULL) {
        return CXPLAT_STATUS_NOT_SUPPORTED; // Not currently supported
    }

    CXPLAT_CERTIFICATE_FILE* CertFile = CredConfig->CertificateFile;

    if (CredConfig->Flags & CXPLAT_CREDENTIAL_FLAG_CLIENT) {
        if (CredConfig->Type != CXPLAT_CREDENTIAL_TYPE_NONE) {
            return CXPLAT_STATUS_NOT_SUPPORTED; // Not supported for client (yet)
        }
    } else {
        if (CredConfig->Type == CXPLAT_CREDENTIAL_TYPE_NONE) {
            return CXPLAT_STATUS_INVALID_PARAMETER; // Required for server
        } else if (CredConfig->Type != CXPLAT_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            return CXPLAT_STATUS_NOT_SUPPORTED; // Only support file currently
        } else if (CertFile == NULL ||
            CertFile->CertificateFile == NULL ||
            CertFile->PrivateKeyFile == NULL) {
            return CXPLAT_STATUS_INVALID_PARAMETER;
        }
    }

    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    int Ret = 0;
    CXPLAT_SEC_CONFIG* SecurityConfig = NULL;

    //
    // Create a security config.
    //

    SecurityConfig = CxPlatAlloc(sizeof(CXPLAT_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    //
    // Create the a SSL context for the security config.
    //

    SecurityConfig->SSLCtx = SSL_CTX_new(TLS_method());
    if (SecurityConfig->SSLCtx == NULL) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_new failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    //
    // Configure the SSL context with the defaults.
    //

    Ret = SSL_CTX_set_min_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_min_proto_version failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_max_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_max_proto_version failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set_ciphersuites(
            SecurityConfig->SSLCtx,
            CXPLAT_TLS_DEFAULT_SSL_CIPHERS);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_ciphersuites failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_default_verify_paths failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set1_groups_list(
            SecurityConfig->SSLCtx,
            CXPLAT_TLS_DEFAULT_SSL_CURVES);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set1_groups_list failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_quic_method(SecurityConfig->SSLCtx, &OpenSslCxPlatCallbacks);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_quic_method failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (CredConfig->Flags & CXPLAT_CREDENTIAL_FLAG_CLIENT) {
        BOOLEAN VerifyServerCertificate = TRUE; // !(Flags & CXPLAT_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION);
        if (!VerifyServerCertificate) {
            SSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER, NULL);
        } else {
            SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);

            if (CxPlatOpenSslClientTrustedCert != NULL) {
                //
                // LINUX_TODO: This is a hack to set a client side trusted cert in order
                //   to verify server cert. Fix this once CxPlat formally supports
                //   passing TLS related config from APP layer to TAL.
                //

                /*Ret =
                    SSL_CTX_load_verify_locations(
                        SecurityConfig->SSLCtx,
                        CxPlatOpenSslClientTrustedCert,
                        NULL);
                if (Ret != 1) {
                    CxPlatTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        ERR_get_error(),
                        "SSL_CTX_load_verify_locations failed");
                    Status = CXPLAT_STATUS_TLS_ERROR;
                    goto Exit;
                }*/
            }
        }
    } else {
        SSL_CTX_set_options(
            SecurityConfig->SSLCtx,
            (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_CIPHER_SERVER_PREFERENCE |
            SSL_OP_NO_ANTI_REPLAY);
        SSL_CTX_clear_options(SecurityConfig->SSLCtx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        SSL_CTX_set_mode(SecurityConfig->SSLCtx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx, CxPlatTlsAlpnSelectCallback, NULL);

        //
        // Set the server certs.
        //

        Ret =
            SSL_CTX_use_PrivateKey_file(
                SecurityConfig->SSLCtx,
                CertFile->PrivateKeyFile,
                SSL_FILETYPE_PEM);
        if (Ret != 1) {
            CxPlatTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_use_PrivateKey_file failed");
            Status = CXPLAT_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret =
            SSL_CTX_use_certificate_chain_file(
                SecurityConfig->SSLCtx,
                CertFile->CertificateFile);
        if (Ret != 1) {
            CxPlatTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_use_certificate_chain_file failed");
            Status = CXPLAT_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = SSL_CTX_check_private_key(SecurityConfig->SSLCtx);
        if (Ret != 1) {
            CxPlatTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_check_private_key failed");
            Status = CXPLAT_STATUS_TLS_ERROR;
            goto Exit;
        }

        SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, UINT32_MAX);
        SSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx, CxPlatTlsClientHelloCallback, NULL);
    }

    //
    // Invoke completion inline.
    //

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfig->Flags & CXPLAT_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = CXPLAT_STATUS_PENDING;
    } else {
        Status = CXPLAT_STATUS_SUCCESS;
    }

Exit:

    if (SecurityConfig != NULL) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    return Status;
}

void
CxPlatTlsSecConfigDelete(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->SSLCtx != NULL) {
        SSL_CTX_free(SecurityConfig->SSLCtx);
        SecurityConfig->SSLCtx = NULL;
    }

    CxPlatFree(SecurityConfig);
}

CXPLAT_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    CXPLAT_TLS* TlsContext = NULL;
    uint16_t ServerNameLength = 0;

    TlsContext = CxPlatAlloc(sizeof(CXPLAT_TLS));
    if (TlsContext == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;

    CxPlatTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

            ServerNameLength = (uint16_t)strnlen(Config->ServerName, CXPLAT_MAX_SNI_LENGTH);
            if (ServerNameLength == CXPLAT_MAX_SNI_LENGTH) {
                CxPlatTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
                Status = CXPLAT_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI = CxPlatAlloc(ServerNameLength + 1);
            if (TlsContext->SNI == NULL) {
                CxPlatTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "SNI",
                    ServerNameLength + 1);
                Status = CXPLAT_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }

            memcpy((char*)TlsContext->SNI, Config->ServerName, ServerNameLength + 1);
        }
    }

    //
    // Create a SSL object for the connection.
    //

    TlsContext->Ssl = SSL_new(Config->SecConfig->SSLCtx);
    if (TlsContext->Ssl == NULL) {
        CxPlatTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SSL_new failed");
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    if (Config->IsServer) {
        SSL_set_accept_state(TlsContext->Ssl);
        //SSL_set_quic_early_data_enabled(TlsContext->Ssl, 1);
    } else {
        SSL_set_connect_state(TlsContext->Ssl);
        SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
        SSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);
    }

    if (SSL_set_quic_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        CxPlatTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SSL_set_quic_transport_params failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }
    CXPLAT_FREE(Config->LocalTPBuffer);

    State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_UNSUPPORTED; // 0-RTT not currently supported.

    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:

    if (TlsContext != NULL) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = NULL;
    }

    return Status;
}

void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        CxPlatTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        if (TlsContext->SNI != NULL) {
            CXPLAT_FREE(TlsContext->SNI);
            TlsContext->SNI = NULL;
        }

        if (TlsContext->Ssl != NULL) {
            SSL_free(TlsContext->Ssl);
            TlsContext->Ssl = NULL;
        }

        CXPLAT_FREE(TlsContext);
        TlsContext = NULL;
    }
}

void
CxPlatTlsReset(
    _In_ CXPLAT_TLS* TlsContext
    )
{
    CxPlatTraceLogConnInfo(
        OpenSslContextReset,
        TlsContext->Connection,
        "Resetting TLS state");

    CXPLAT_DBG_ASSERT(TlsContext->IsServer == FALSE);

    //
    // Free the old SSL state.
    //

    if (TlsContext->Ssl != NULL) {
        SSL_free(TlsContext->Ssl);
        TlsContext->Ssl = NULL;
    }

    //
    // Create a new SSL state.
    //

    TlsContext->Ssl = SSL_new(TlsContext->SecConfig->SSLCtx);
    if (TlsContext->Ssl == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SSL_new failed");
        CXPLAT_DBG_ASSERT(FALSE);
        goto Exit;
    }

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    SSL_set_connect_state(TlsContext->Ssl);
    SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
    SSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);

    /* TODO - Figure out if this is necessary.
    if (SSL_set_quic_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SSL_set_quic_transport_params failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }*/

Exit:

    return;
}

CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength) const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    int Ret = 0;
    int Err = 0;

    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        TlsContext->ResultFlags = CXPLAT_TLS_RESULT_ERROR;

        CxPlatTraceLogConnVerbose(
            OpenSsslIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
        goto Exit;
    }

    if (*BufferLength != 0) {
        CxPlatTraceLogConnVerbose(
            OpenSslProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
    }

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (SSL_provide_quic_data(
            TlsContext->Ssl,
            (OSSL_ENCRYPTION_LEVEL)TlsContext->State->ReadKey,
            Buffer,
            *BufferLength) != 1) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        goto Exit;
    }

    if (!State->HandshakeComplete) {
        Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret <= 0) {
            Err = SSL_get_error(TlsContext->Ssl, Ret);
            switch (Err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                goto Exit;

            case SSL_ERROR_SSL:
                CxPlatTraceLogConnError(
                    OpenSslHandshakeErrorStr,
                    TlsContext->Connection,
                    "TLS handshake error: %s",
                    ERR_error_string(ERR_get_error(), NULL));
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;

            default:
                CxPlatTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        if (!TlsContext->IsServer) {
            const uint8_t* NegotiatedAlpn;
            uint32_t NegotiatedAlpnLength;
            SSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn, &NegotiatedAlpnLength);
            if (NegotiatedAlpnLength == 0) {
                CxPlatTraceLogConnError(
                    OpenSslAlpnNegotiationFailure,
                    TlsContext->Connection,
                    "Failed to negotiate ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (NegotiatedAlpnLength > UINT8_MAX) {
                CxPlatTraceLogConnError(
                    OpenSslInvalidAlpnLength,
                    TlsContext->Connection,
                    "Invalid negotiated ALPN length");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            TlsContext->State->NegotiatedAlpn =
                CxPlatTlsAlpnFindInList(
                    TlsContext->AlpnBufferLength,
                    TlsContext->AlpnBuffer,
                    (uint8_t)NegotiatedAlpnLength,
                    NegotiatedAlpn);
            if (TlsContext->State->NegotiatedAlpn == NULL) {
                CxPlatTraceLogConnError(
                    OpenSslNoMatchingAlpn,
                    TlsContext->Connection,
                    "Failed to find a matching ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        CxPlatTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "Handshake complete");
        State->HandshakeComplete = TRUE;
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_COMPLETE;

        if (TlsContext->IsServer) {
            TlsContext->State->ReadKey = CXPLAT_PACKET_KEY_1_RTT;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
        } else {
            const uint8_t* TransportParams;
            size_t TransportParamLen;
            SSL_get_peer_quic_transport_params(
                    TlsContext->Ssl, &TransportParams, &TransportParamLen);
            if (TransportParams == NULL || TransportParamLen == 0) {
                CxPlatTraceLogConnError(
                    OpenSslMissingTransportParameters,
                    TlsContext->Connection,
                    "No transport parameters received");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (!TlsContext->ReceiveTPCallback(
                    TlsContext->Connection,
                    (uint16_t)TransportParamLen,
                    TransportParams)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }
    }

    Ret = SSL_do_handshake(TlsContext->Ssl);
    if (Ret != 1) {
        Err = SSL_get_error(TlsContext->Ssl, Ret);
        switch (Err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            goto Exit;

        case SSL_ERROR_SSL:
            CxPlatTraceLogConnError(
                OpenSslHandshakeErrorStr,
                TlsContext->Connection,
                "TLS handshake error: %s",
                ERR_error_string(ERR_get_error(), NULL));
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;

        default:
            CxPlatTraceLogConnError(
                OpenSslHandshakeError,
                TlsContext->Connection,
                "TLS handshake error: %d",
                Err);
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

Exit:

    if (!(TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR)) {
        if (State->WriteKeys[CXPLAT_PACKET_KEY_HANDSHAKE] != NULL &&
            State->BufferOffsetHandshake == 0) {
            State->BufferOffsetHandshake = State->BufferTotalLength;
            CxPlatTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                State->BufferOffsetHandshake);
        }
        if (State->WriteKeys[CXPLAT_PACKET_KEY_1_RTT] != NULL &&
            State->BufferOffset1Rtt == 0) {
            State->BufferOffset1Rtt = State->BufferTotalLength;
            CxPlatTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                State->BufferOffset1Rtt);
        }
    }

    return TlsContext->ResultFlags;
}

CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessDataComplete(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ uint32_t * BufferConsumed
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferConsumed);
    return CXPLAT_TLS_RESULT_ERROR;
}

CXPLAT_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return CXPLAT_STATUS_NOT_SUPPORTED;
}

CXPLAT_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return CXPLAT_STATUS_NOT_SUPPORTED;
}

//
// Crypto / Key Functionality
//

#ifdef DEBUG
void
CxPlatTlsLogSecret(
    _In_z_ const char* const Prefix,
    _In_reads_(Length)
        const uint8_t* const Secret,
    _In_ uint32_t Length
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    char SecretStr[256 + 1] = {0};
    CXPLAT_DBG_ASSERT(Length * 2 < sizeof(SecretStr));
    for (uint8_t i = 0; i < Length; i++) {
        SecretStr[i*2]     = HEX_TO_CHAR(Secret[i] >> 4);
        SecretStr[i*2 + 1] = HEX_TO_CHAR(Secret[i] & 0xf);
    }
    CxPlatTraceLogVerbose(
        OpenSslLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
}
#else
#define CxPlatTlsLogSecret(Prefix, Secret, Length) UNREFERENCED_PARAMETER(Prefix);
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t HashLength,
    _Out_writes_all_(5 + CXPLAT_HKDF_PREFIX_LEN + strlen(Label))
        uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    CXPLAT_DBG_ASSERT(strlen(Label) <= UINT8_MAX - CXPLAT_HKDF_PREFIX_LEN);
    uint8_t LabelLength = (uint8_t)strlen(Label);

    Data[0] = HashLength >> 8;
    Data[1] = HashLength & 0xff;
    Data[2] = CXPLAT_HKDF_PREFIX_LEN + LabelLength;
    memcpy(Data + 3, CXPLAT_HKDF_PREFIX, CXPLAT_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + CXPLAT_HKDF_PREFIX_LEN, Label, LabelLength);
    Data[3 + CXPLAT_HKDF_PREFIX_LEN + LabelLength] = 0;
    *DataLength = 3 + CXPLAT_HKDF_PREFIX_LEN + LabelLength + 1;

    Data[*DataLength] = 0x1;
    *DataLength += 1;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
CxPlatHkdfExpandLabel(
    _In_ CXPLAT_HASH* Hash,
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLength,
    _In_ uint32_t OutputLength, // Writes CxPlatHashLength(HashType) bytes.
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    uint8_t LabelBuffer[64];
    uint32_t LabelLength = sizeof(LabelBuffer);

    _Analysis_assume_(strlen(Label) <= 23);
    CxPlatHkdfFormatLabel(Label, KeyLength, LabelBuffer, &LabelLength);

    return
        CxPlatHashCompute(
            Hash,
            LabelBuffer,
            LabelLength,
            OutputLength,
            Output);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
CxPlatTlsDeriveInitialSecrets(
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _In_ uint8_t CIDLength,
    _Out_ CXPLAT_SECRET *ClientInitial,
    _Out_ CXPLAT_SECRET *ServerInitial
    )
{
    CXPLAT_STATUS Status;
    CXPLAT_HASH* InitialHash = NULL;
    CXPLAT_HASH* DerivedHash = NULL;
    uint8_t InitialSecret[CXPLAT_HASH_SHA256_SIZE];

    CxPlatTlsLogSecret("init cid", CID, CIDLength);

    Status =
        CxPlatHashCreate(
            CXPLAT_HASH_SHA256,
            Salt,
            CXPLAT_VERSION_SALT_LENGTH,
            &InitialHash);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    //
    // Extract secret for client and server secret expansion.
    //
    Status =
        CxPlatHashCompute(
            InitialHash,
            CID,
            CIDLength,
            sizeof(InitialSecret),
            InitialSecret);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    CxPlatTlsLogSecret("init secret", InitialSecret, sizeof(InitialSecret));

    //
    // Create hash for client and server secret expansion.
    //
    Status =
        CxPlatHashCreate(
            CXPLAT_HASH_SHA256,
            InitialSecret,
            sizeof(InitialSecret),
            &DerivedHash);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand client secret.
    //
    ClientInitial->Hash = CXPLAT_HASH_SHA256;
    ClientInitial->Aead = CXPLAT_AEAD_AES_128_GCM;
    Status =
        CxPlatHkdfExpandLabel(
            DerivedHash,
            "client in",
            sizeof(InitialSecret),
            CXPLAT_HASH_SHA256_SIZE,
            ClientInitial->Secret);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand server secret.
    //
    ServerInitial->Hash = CXPLAT_HASH_SHA256;
    ServerInitial->Aead = CXPLAT_AEAD_AES_128_GCM;
    Status =
        CxPlatHkdfExpandLabel(
            DerivedHash,
            "server in",
            sizeof(InitialSecret),
            CXPLAT_HASH_SHA256_SIZE,
            ServerInitial->Secret);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

Error:

    CxPlatHashFree(InitialHash);
    CxPlatHashFree(DerivedHash);

    CxPlatSecureZeroMemory(InitialSecret, sizeof(InitialSecret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
CxPlatPacketKeyDerive(
    _In_ CXPLAT_PACKET_KEY_TYPE KeyType,
    _In_ const CXPLAT_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ CXPLAT_PACKET_KEY **NewKey
    )
{
    const uint16_t SecretLength = CxPlatHashLength(Secret->Hash);
    const uint16_t KeyLength = CxPlatKeyLength(Secret->Aead);

    CXPLAT_DBG_ASSERT(SecretLength >= KeyLength);
    CXPLAT_DBG_ASSERT(SecretLength >= CXPLAT_IV_LENGTH);
    CXPLAT_DBG_ASSERT(SecretLength <= CXPLAT_HASH_MAX_SIZE);

    CxPlatTlsLogSecret(SecretName, Secret->Secret, SecretLength);

    const uint16_t PacketKeyLength =
        sizeof(CXPLAT_PACKET_KEY) +
        (KeyType == CXPLAT_PACKET_KEY_1_RTT ? sizeof(CXPLAT_SECRET) : 0);
    CXPLAT_PACKET_KEY *Key = CXPLAT_ALLOC_NONPAGED(PacketKeyLength);
    if (Key == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_PACKET_KEY",
            PacketKeyLength);
        return CXPLAT_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(Key, sizeof(CXPLAT_PACKET_KEY));
    Key->Type = KeyType;

    CXPLAT_HASH* Hash = NULL;
    uint8_t Temp[CXPLAT_HASH_MAX_SIZE];

    CXPLAT_STATUS Status =
        CxPlatHashCreate(
            Secret->Hash,
            Secret->Secret,
            SecretLength,
            &Hash);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic iv",
            CXPLAT_IV_LENGTH,
            SecretLength,
            Temp);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    memcpy(Key->Iv, Temp, CXPLAT_IV_LENGTH);
    CxPlatTlsLogSecret("static iv", Key->Iv, CXPLAT_IV_LENGTH);

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic key",
            KeyLength,
            SecretLength,
            Temp);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    CxPlatTlsLogSecret("key", Temp, KeyLength);

    Status =
        CxPlatKeyCreate(
            Secret->Aead,
            Temp,
            &Key->PacketKey);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            CxPlatHkdfExpandLabel(
                Hash,
                "quic hp",
                KeyLength,
                SecretLength,
                Temp);
        if (CXPLAT_FAILED(Status)) {
            goto Error;
        }

        CxPlatTlsLogSecret("hp", Temp, KeyLength);

        Status =
            CxPlatHpKeyCreate(
                Secret->Aead,
                Temp,
                &Key->HeaderKey);
        if (CXPLAT_FAILED(Status)) {
            goto Error;
        }
    }

    if (KeyType == CXPLAT_PACKET_KEY_1_RTT) {
        CxPlatCopyMemory(Key->TrafficSecret, Secret, sizeof(CXPLAT_SECRET));
    }

    *NewKey = Key;
    Key = NULL;

Error:

    CxPlatPacketKeyFree(Key);
    CxPlatHashFree(Hash);

    CxPlatSecureZeroMemory(Temp, sizeof(Temp));

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(NewReadKey != NULL, _At_(*NewReadKey, __drv_allocatesMem(Mem)))
_When_(NewWriteKey != NULL, _At_(*NewWriteKey, __drv_allocatesMem(Mem)))
CXPLAT_STATUS
CxPlatPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ CXPLAT_PACKET_KEY** NewReadKey,
    _Out_opt_ CXPLAT_PACKET_KEY** NewWriteKey
    )
{
    CXPLAT_STATUS Status;
    CXPLAT_SECRET ClientInitial, ServerInitial;
    CXPLAT_PACKET_KEY* ReadKey = NULL, *WriteKey = NULL;

    Status =
        CxPlatTlsDeriveInitialSecrets(
            Salt,
            CID,
            CIDLength,
            &ClientInitial,
            &ServerInitial);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    if (NewWriteKey != NULL) {
        Status =
            CxPlatPacketKeyDerive(
                CXPLAT_PACKET_KEY_INITIAL,
                IsServer ? &ServerInitial : &ClientInitial,
                IsServer ? "srv secret" : "cli secret",
                TRUE,
                &WriteKey);
        if (CXPLAT_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewReadKey != NULL) {
        Status =
            CxPlatPacketKeyDerive(
                CXPLAT_PACKET_KEY_INITIAL,
                IsServer ? &ClientInitial : &ServerInitial,
                IsServer ? "cli secret" : "srv secret",
                TRUE,
                &ReadKey);
        if (CXPLAT_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewWriteKey != NULL) {
        *NewWriteKey = WriteKey;
        WriteKey = NULL;
    }

    if (NewReadKey != NULL) {
        *NewReadKey = ReadKey;
        ReadKey = NULL;
    }

Error:

    CxPlatPacketKeyFree(ReadKey);
    CxPlatPacketKeyFree(WriteKey);

    CxPlatSecureZeroMemory(ClientInitial.Secret, sizeof(ClientInitial.Secret));
    CxPlatSecureZeroMemory(ServerInitial.Secret, sizeof(ServerInitial.Secret));

    return Status;
}

void
CxPlatPacketKeyFree(
    _In_opt_ CXPLAT_PACKET_KEY* Key
    )
{
    if (Key != NULL) {
        CxPlatKeyFree(Key->PacketKey);
        CxPlatHpKeyFree(Key->HeaderKey);
        if (Key->Type >= CXPLAT_PACKET_KEY_1_RTT) {
            CxPlatSecureZeroMemory(Key->TrafficSecret, sizeof(CXPLAT_SECRET));
        }
        CXPLAT_FREE(Key);
    }
}

CXPLAT_STATUS
CxPlatPacketKeyUpdate(
    _In_ CXPLAT_PACKET_KEY* OldKey,
    _Out_ CXPLAT_PACKET_KEY** NewKey
    )
{
    if (OldKey->Type != CXPLAT_PACKET_KEY_1_RTT) {
        return CXPLAT_STATUS_INVALID_STATE;
    }

    CXPLAT_HASH* Hash = NULL;
    CXPLAT_SECRET NewTrafficSecret;
    const uint16_t SecretLength = CxPlatHashLength(OldKey->TrafficSecret->Hash);

    CXPLAT_STATUS Status =
        CxPlatHashCreate(
            OldKey->TrafficSecret->Hash,
            OldKey->TrafficSecret->Secret,
            SecretLength,
            &Hash);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic ku",
            SecretLength,
            SecretLength,
            NewTrafficSecret.Secret);
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    NewTrafficSecret.Hash = OldKey->TrafficSecret->Hash;
    NewTrafficSecret.Aead = OldKey->TrafficSecret->Aead;

    Status =
        CxPlatPacketKeyDerive(
            CXPLAT_PACKET_KEY_1_RTT,
            &NewTrafficSecret,
            "update traffic secret",
            FALSE,
            NewKey);

    CxPlatSecureZeroMemory(&NewTrafficSecret, sizeof(CXPLAT_SECRET));
    CxPlatSecureZeroMemory(OldKey->TrafficSecret, sizeof(CXPLAT_SECRET));

Error:

    CxPlatHashFree(Hash);

    return Status;
}

CXPLAT_STATUS
CxPlatKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_KEY** NewKey
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    const EVP_CIPHER *Aead;

    EVP_CIPHER_CTX* CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_new failed");
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        Aead = EVP_aes_128_gcm();
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        Aead = EVP_aes_256_gcm();
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        Aead = EVP_chacha20_poly1305();
        break;
    default:
        Status = CXPLAT_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (EVP_CipherInit_ex(CipherCtx, Aead, NULL, RawKey, NULL, 1) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CipherInit_ex failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, CXPLAT_IV_LENGTH, NULL) != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = (CXPLAT_KEY*)CipherCtx;
    CipherCtx = NULL;

Exit:

    CxPlatKeyFree((CXPLAT_KEY*)CipherCtx);

    return Status;
}

void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    )
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)Key);
}

CXPLAT_STATUS
CxPlatEncrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > CXPLAT_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= CXPLAT_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t PlainTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;
    uint8_t *Tag = Buffer + PlainTextLength;
    int OutLen;

    EVP_CIPHER_CTX* CipherCtx = (EVP_CIPHER_CTX*)Key;

    if (EVP_EncryptInit_ex(CipherCtx, NULL, NULL, NULL, Iv) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptInit_ex failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (AuthData != NULL &&
        EVP_EncryptUpdate(CipherCtx, NULL, &OutLen, AuthData, (int)AuthDataLength) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate (AD) failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (EVP_EncryptUpdate(CipherCtx, Buffer, &OutLen, Buffer, (int)PlainTextLength) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate (Cipher) failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (EVP_EncryptFinal_ex(CipherCtx, Tag, &OutLen) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptFinal_ex failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, CXPLAT_ENCRYPTION_OVERHEAD, Tag) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    return CXPLAT_STATUS_SUCCESS;
}

CXPLAT_STATUS
CxPlatDecrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t CipherTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;
    uint8_t *Tag = Buffer + CipherTextLength;
    int OutLen;

    EVP_CIPHER_CTX* CipherCtx = (EVP_CIPHER_CTX*)Key;

    if (EVP_DecryptInit_ex(CipherCtx, NULL, NULL, NULL, Iv) != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptInit_ex failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (AuthData != NULL &&
        EVP_DecryptUpdate(CipherCtx, NULL, &OutLen, AuthData, (int)AuthDataLength) != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptUpdate (AD) failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (EVP_DecryptUpdate(CipherCtx, Buffer, &OutLen, Buffer, (int)CipherTextLength) != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptUpdate (Cipher) failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_TAG, CXPLAT_ENCRYPTION_OVERHEAD, Tag) != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    if (EVP_DecryptFinal_ex(CipherCtx, Tag, &OutLen) != 1) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptFinal_ex failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }

    return CXPLAT_STATUS_SUCCESS;
}

CXPLAT_STATUS
CxPlatHpKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_HP_KEY** NewKey
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    const EVP_CIPHER *Aead;

    EVP_CIPHER_CTX* CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Cipherctx alloc failed");
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        Aead = EVP_aes_128_ecb();
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        Aead = EVP_aes_256_ecb();
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        Aead = EVP_chacha20_poly1305();
        break;
    default:
        Status = CXPLAT_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, Aead, NULL, RawKey, NULL) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptInit_ex failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = (CXPLAT_HP_KEY*)CipherCtx;
    CipherCtx = NULL;

Exit:

    CxPlatHpKeyFree((CXPLAT_HP_KEY*)CipherCtx);

    return Status;
}

void
CxPlatHpKeyFree(
    _In_opt_ CXPLAT_HP_KEY* Key
    )
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)Key);
}

CXPLAT_STATUS
CxPlatHpComputeMask(
    _In_ CXPLAT_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize) const uint8_t* const Cipher,
    _Out_writes_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize) uint8_t* Mask
    )
{
    int OutLen = 0;
    if (EVP_EncryptUpdate((EVP_CIPHER_CTX*)Key, Mask, &OutLen, Cipher, CXPLAT_HP_SAMPLE_LENGTH * BatchSize) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate failed");
        return CXPLAT_STATUS_TLS_ERROR;
    }
    return CXPLAT_STATUS_SUCCESS;
}

//
// Hash abstraction
//

typedef struct CXPLAT_HASH {
    //
    // The message digest.
    //
    const EVP_MD *Md;

    //
    // Context used for hashing.
    //
    HMAC_CTX* HashContext;

} CXPLAT_HASH;

CXPLAT_STATUS
CxPlatHashCreate(
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(SaltLength) const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ CXPLAT_HASH** NewHash
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    const EVP_MD *Md;

    HMAC_CTX* HashContext = HMAC_CTX_new();
    if (HashContext == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_CTX_new failed");
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (HashType) {
    case CXPLAT_HASH_SHA256:
        Md = EVP_sha256();
        break;
    case CXPLAT_HASH_SHA384:
        Md = EVP_sha384();
        break;
    case CXPLAT_HASH_SHA512:
        Md = EVP_sha512();
        break;
    default:
        Status = CXPLAT_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (HMAC_Init_ex(HashContext, Salt, SaltLength, Md, NULL) != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Init_ex failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewHash = (CXPLAT_HASH*)HashContext;
    HashContext = NULL;

Exit:

    CxPlatHashFree((CXPLAT_HASH*)HashContext);

    return Status;
}

void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    HMAC_CTX_free((HMAC_CTX*)Hash);
}

CXPLAT_STATUS
CxPlatHashCompute(
    _In_ CXPLAT_HASH* Hash,
    _In_reads_(InputLength) const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength,
    _Out_writes_all_(OutputLength) uint8_t* const Output
    )
{
    HMAC_CTX* HashContext = (HMAC_CTX*)Hash;

    if (!HMAC_Init_ex(HashContext, NULL, 0, NULL, NULL)) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Init_ex(NULL) failed");
        return CXPLAT_STATUS_INTERNAL_ERROR;
    }

    if (!HMAC_Update(HashContext, Input, InputLength)) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Update failed");
        return CXPLAT_STATUS_INTERNAL_ERROR;
    }

    uint32_t ActualOutputSize = OutputLength;
    if (!HMAC_Final(HashContext, Output, &ActualOutputSize)) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Final failed");
        return CXPLAT_STATUS_INTERNAL_ERROR;
    }

    CXPLAT_FRE_ASSERT(ActualOutputSize == OutputLength);
    return CXPLAT_STATUS_SUCCESS;
}
