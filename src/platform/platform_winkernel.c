/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer.

Environment:

    Windows Kernel Mode

--*/

#include "platform_internal.h"
#ifdef CXPLAT_CLOG
#include "platform_winkernel.c.clog.h"
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation                          = 0
} SYSTEM_INFORMATION_CLASS;

NTSYSAPI // Copied from zwapi.h.
NTSTATUS
NTAPI
ZwQuerySystemInformation (
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __out_bcount_part_opt(SystemInformationLength, *ReturnLength) PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef struct _SYSTEM_BASIC_INFORMATION {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;

    //
    // WARNING: The following fields are 32-bit and may get
    // capped to MAXULONG on systems with a lot of RAM!
    //
    // Use SYSTEM_PHYSICAL_MEMORY_INFORMATION instead.
    //

    ULONG NumberOfPhysicalPages;      // Deprecated, do not use.
    ULONG LowestPhysicalPageNumber;   // Deprecated, do not use.
    ULONG HighestPhysicalPageNumber;  // Deprecated, do not use.

    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;


uint64_t CxPlatPlatformPerfFreq;
uint64_t CxPlatTotalMemory;
CXPLAT_PLATFORM CxPlatPlatform = { NULL, NULL };

INITCODE
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformSystemLoad(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

#ifdef CXPLAT_EVENTS_MANIFEST_ETW
    EventRegisterMicrosoft_CxPlat();
#endif

#ifdef CXPLAT_TELEMETRY_ASSERTS
    InitializeTelemetryAssertsKM(RegistryPath);
#endif

    CxPlatPlatform.DriverObject = DriverObject;
    (VOID)KeQueryPerformanceCounter((LARGE_INTEGER*)&CxPlatPlatformPerfFreq);
    CxPlatPlatform.RngAlgorithm = NULL;

    CxPlatTraceLogInfo(
        WindowsKernelLoaded,
        "[ sys] Loaded");
}

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformSystemUnload(
    void
    )
{
    PAGED_CODE();

    CxPlatTraceLogInfo(
        WindowsKernelUnloaded,
        "[ sys] Unloaded");

#ifdef CXPLAT_TELEMETRY_ASSERTS
    UninitializeTelemetryAssertsKM();
#endif

#ifdef CXPLAT_EVENTS_MANIFEST_ETW
    EventUnregisterMicrosoft_CxPlat();
#endif
}

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
CxPlatPlatformInitialize(
    void
    )
{
    SYSTEM_BASIC_INFORMATION Sbi;

    PAGED_CODE();

    CXPLAT_STATUS Status =
        BCryptOpenAlgorithmProvider(
            &CxPlatPlatform.RngAlgorithm,
            BCRYPT_RNG_ALGORITHM,
            NULL,
            BCRYPT_PROV_DISPATCH);
    if (CXPLAT_FAILED(Status)) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptOpenAlgorithmProvider (RNG)");
        goto Error;
    }
    CXPLAT_DBG_ASSERT(CxPlatPlatform.RngAlgorithm != NULL);

    Status =
        ZwQuerySystemInformation(
            SystemBasicInformation, &Sbi, sizeof(Sbi), NULL);
    if (CXPLAT_FAILED(Status)) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "ZwQuerySystemInformation(SystemBasicInformation)");
        goto Error;
    }

    Status = CxPlatTlsLibraryInitialize();
    if (CXPLAT_FAILED(Status)) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatTlsLibraryInitialize");
        goto Error;
    }

    //
    // TODO - Apparently this can be increased via hot memory add. Figure out
    // how to know when to update this value.
    //
    CxPlatTotalMemory = (uint64_t)Sbi.NumberOfPhysicalPages * (uint64_t)Sbi.PageSize;

    CxPlatTraceLogInfo(
        WindowsKernelInitialized,
        "[ sys] Initialized (PageSize = %u bytes; AvailMem = %llu bytes)",
        Sbi.PageSize,
        CxPlatTotalMemory);

Error:

    if (CXPLAT_FAILED(Status)) {
        if (CxPlatPlatform.RngAlgorithm != NULL) {
            BCryptCloseAlgorithmProvider(CxPlatPlatform.RngAlgorithm, 0);
            CxPlatPlatform.RngAlgorithm = NULL;
        }
    }

    return Status;
}

PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformUninitialize(
    void
    )
{
    PAGED_CODE();
    CxPlatTlsLibraryUninitialize();
    BCryptCloseAlgorithmProvider(CxPlatPlatform.RngAlgorithm, 0);
    CxPlatPlatform.RngAlgorithm = NULL;
    CxPlatTraceLogInfo(
        WindowsKernelUninitialized,
        "[ sys] Uninitialized");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    )
{
    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Line);
    UNREFERENCED_PARAMETER(Expr);
    CxPlatTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    //
    // Use the algorithm we initialized for DISPATCH_LEVEL usage.
    //
    CXPLAT_DBG_ASSERT(CxPlatPlatform.RngAlgorithm != NULL);
    return (CXPLAT_STATUS)
        BCryptGenRandom(
            CxPlatPlatform.RngAlgorithm,
            (uint8_t*)Buffer,
            BufferLen,
            0);
}

#ifdef CXPLAT_EVENTS_MANIFEST_ETW

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
    )
{
    UNREFERENCED_PARAMETER(SourceId);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(MatchAnyKeyword);
    UNREFERENCED_PARAMETER(MatchAllKeyword);
    UNREFERENCED_PARAMETER(FilterData);

    switch(ControlCode) {
    case EVENT_CONTROL_CODE_ENABLE_PROVIDER:
    case EVENT_CONTROL_CODE_CAPTURE_STATE:
        if (CallbackContext == &MICROSOFT_MSCXPLAT_PROVIDER_Context) {
            CxPlatTraceRundown();
        }
        break;
    case EVENT_CONTROL_CODE_DISABLE_PROVIDER:
    default:
        break;
    }
}

#endif
