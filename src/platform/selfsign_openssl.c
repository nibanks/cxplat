/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    OpenSSL implementation for generating the self-signed certificate.

--*/

#define CXPLAT_TEST_APIS 1
#define _CRT_SECURE_NO_WARNINGS

#include "platform_internal.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/ec.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#ifdef CXPLAT_CLOG
#include "selfsign_openssl.c.clog.h"
#endif

//
// Generates a self signed cert using low level OpenSSL APIs.
//
CXPLAT_STATUS
CxPlatTlsGenerateSelfSignedCert(
    _In_z_ char *CertFileName,
    _In_z_ char *PrivateKeyFileName,
    _In_z_ char *SNI
    )
{
    CXPLAT_STATUS Status = CXPLAT_STATUS_SUCCESS;
    int Ret = 0;
    EVP_PKEY *PKey = NULL;
    EVP_PKEY_CTX * EcKeyCtx = NULL;
    X509 *X509 = NULL;
    X509_NAME *Name = NULL;
    FILE *Fd = NULL;

    PKey = EVP_PKEY_new();

    if (PKey == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_new() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    EcKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EcKeyCtx == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_CTX_new_id() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen_init(EcKeyCtx);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_keygen_init() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen(EcKeyCtx, &PKey);
    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_keygen() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509 = X509_new();

    if (X509 == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_new() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = ASN1_INTEGER_set(X509_get_serialNumber(X509), 1);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "ASN1_INTEGER_set() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509_gmtime_adj(X509_get_notBefore(X509), 0);
    X509_gmtime_adj(X509_get_notAfter(X509), 31536000L);

    X509_set_pubkey(X509, PKey);

    Name = X509_get_subject_name(X509);

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "C",
            MBSTRING_ASC,
            (unsigned char *)"CA",
            -1,
            -1,
            0);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "O",
            MBSTRING_ASC,
            (unsigned char *)"Microsoft",
            -1,
            -1,
            0);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "CN",
            MBSTRING_ASC,
            (unsigned char *)SNI,
            -1,
            -1,
            0);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_set_issuer_name(X509, Name);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_set_issuer_name() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_sign(X509, PKey, EVP_sha256());

    if (Ret <= 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_sign() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Fd = fopen(PrivateKeyFileName, "wb");

    if (Fd == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "fopen() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_PrivateKey(Fd, PKey, NULL, NULL, 0, NULL, NULL);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PEM_write_PrivateKey() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

    Fd = fopen(CertFileName, "wb");

    if (Fd == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "fopen() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_X509(Fd, X509);

    if (Ret != 1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PEM_write_X509() failed");
        Status = CXPLAT_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

Exit:

    if (PKey != NULL) {
        EVP_PKEY_free(PKey);
        PKey= NULL;
    }

    if (EcKeyCtx != NULL) {
        EVP_PKEY_CTX_free(EcKeyCtx);
        EcKeyCtx = NULL;
    }

    if (X509 != NULL) {
        X509_free(X509);
        X509 = NULL;
    }

    if (Fd != NULL) {
        fclose(Fd);
        Fd = NULL;
    }

    return Status;
}

static char* CxPlatTestCertFilename = (char*)"localhost_cert.pem";
static char* CxPlatTestPrivateKeyFilename = (char*)"localhost_key.pem";

#ifndef MAX_PATH
#define MAX_PATH 50
#endif

typedef struct CXPLAT_CREDENTIAL_CONFIG_INTERNAL {
    CXPLAT_CREDENTIAL_CONFIG;
    CXPLAT_CERTIFICATE_FILE CertFile;
#ifdef _WIN32
    char TempPath [MAX_PATH];
#else
    const char* TempDir;
#endif
    char CertFilepath[MAX_PATH];
    char PrivateKeyFilepath[MAX_PATH];

} CXPLAT_CREDENTIAL_CONFIG_INTERNAL;

#define TEMP_DIR_TEMPLATE "/tmp/quictest.XXXXXX"

_IRQL_requires_max_(PASSIVE_LEVEL)
const CXPLAT_CREDENTIAL_CONFIG*
CxPlatPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type
    )
{
    UNREFERENCED_PARAMETER(Type);

    CXPLAT_CREDENTIAL_CONFIG_INTERNAL* Params =
        malloc(sizeof(CXPLAT_CREDENTIAL_CONFIG_INTERNAL) + sizeof(TEMP_DIR_TEMPLATE));
    if (Params == NULL) {
        return NULL;
    }

    CxPlatZeroMemory(Params, sizeof(*Params));
    Params->Type = CXPLAT_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Params->CertificateFile = &Params->CertFile;
    Params->CertFile.CertificateFile = Params->CertFilepath;
    Params->CertFile.PrivateKeyFile = Params->PrivateKeyFilepath;

#ifdef _WIN32

    DWORD PathStatus = GetTempPathA(sizeof(Params->TempPath), Params->TempPath);
    if (PathStatus > MAX_PATH || PathStatus <= 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "GetTempPathA failed");
        goto Error;
    }

    UINT TempFileStatus =
        GetTempFileNameA(
            Params->TempPath,
            "cxplatopensslcert",
            0,
            Params->CertFilepath);
    if (TempFileStatus == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "GetTempFileNameA Cert Path failed");
        goto Error;
    }

    TempFileStatus =
        GetTempFileNameA(
            Params->TempPath,
            "cxplatopensslkey",
            0,
            Params->PrivateKeyFilepath);
    if (TempFileStatus == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "GetTempFileNameA Private Key failed");
        goto Error;
    }

#else
    char* Template = (char*)(Params + 1);
    memcpy(Template, TEMP_DIR_TEMPLATE, sizeof(TEMP_DIR_TEMPLATE));

    Params->TempDir = mkdtemp(Template);
    if (Params->TempDir == NULL) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "mkdtemp failed");
        goto Error;
    }

    CxPlatCopyMemory(
        Params->CertFilepath,
        Params->TempDir,
        strlen(Params->TempDir));
    CxPlatCopyMemory(
        Params->CertFilepath + strlen(Params->TempDir),
        "/",
        1);
    CxPlatCopyMemory(
        Params->CertFilepath + strlen(Params->TempDir) + 1,
        CxPlatTestCertFilename,
        strlen(CxPlatTestCertFilename));
    CxPlatCopyMemory(
        Params->PrivateKeyFilepath,
        Params->TempDir,
        strlen(Params->TempDir));
    CxPlatCopyMemory(
        Params->PrivateKeyFilepath + strlen(Params->TempDir),
        "/",
        1);
    CxPlatCopyMemory(
        Params->PrivateKeyFilepath + strlen(Params->TempDir) + 1,
        CxPlatTestPrivateKeyFilename,
        strlen(CxPlatTestPrivateKeyFilename));
#endif

    if (CXPLAT_FAILED(
        CxPlatTlsGenerateSelfSignedCert(
            Params->CertFilepath,
            Params->PrivateKeyFilepath,
            (char *)"localhost"))) {
        goto Error;
    }

    return (CXPLAT_CREDENTIAL_CONFIG*)Params;

Error:

#if _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#endif
    free(Params);

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatFreeSelfSignedCert(
    _In_ const CXPLAT_CREDENTIAL_CONFIG* _Params
    )
{
    CXPLAT_CREDENTIAL_CONFIG_INTERNAL* Params =
        (CXPLAT_CREDENTIAL_CONFIG_INTERNAL*)_Params;

#ifdef _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#else
    char RmCmd[32] = {0};
    strncpy(RmCmd, "rm -rf ", 7 + 1);
    strcat(RmCmd, Params->TempDir);
    if (system(RmCmd) == -1) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Tempdir del error");
    }
#endif

    free(Params);
}
