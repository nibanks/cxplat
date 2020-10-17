/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Stub implementation for generating the self-signed certificate.

--*/

#define CXPLAT_TEST_APIS 1

#include "platform_internal.h"
#ifdef CXPLAT_CLOG
#include "selfsign_stub.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
const CXPLAT_CREDENTIAL_CONFIG*
CxPlatPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type
    )
{
    UNREFERENCED_PARAMETER(Type);

    CXPLAT_CREDENTIAL_CONFIG* Params = malloc(sizeof(CXPLAT_CREDENTIAL_CONFIG));
    if (Params != NULL) {
        CxPlatZeroMemory(Params, sizeof(*Params));
        Params->Type = CXPLAT_CREDENTIAL_TYPE_NULL;
    }
    return Params;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatFreeSelfSignedCert(
    _In_ const CXPLAT_CREDENTIAL_CONFIG* Params
    )
{
    free((void*)Params);
}
