/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Platform Abstraction Layer.

Environment:

    Windows User Mode

--*/

#include "platform_internal.h"
#ifdef CXPLAT_CLOG
#include "platform_winuser.c.clog.h"
#endif

uint64_t CxPlatPlatformPerfFreq;
uint64_t CxPlatTotalMemory;
CXPLAT_PLATFORM CxPlatPlatform = { NULL };
CXPLAT_PROCESSOR_INFO* CxPlatProcessorInfo;
uint64_t* CxPlatNumaMasks;
uint32_t* CxPlatProcessorGroupOffsets;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformSystemLoad(
    void
    )
{
#ifdef CXPLAT_EVENTS_MANIFEST_ETW
    EventRegisterMicrosoft_CxPlat();
#endif

    (void)QueryPerformanceFrequency((LARGE_INTEGER*)&CxPlatPlatformPerfFreq);
    CxPlatPlatform.Heap = NULL;

    CxPlatTraceLogInfo(
        WindowsUserLoaded,
        "[ dll] Loaded");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformSystemUnload(
    void
    )
{
    CxPlatTraceLogInfo(
        WindowsUserUnloaded,
        "[ dll] Unloaded");

#ifdef CXPLAT_EVENTS_MANIFEST_ETW
    EventUnregisterMicrosoft_CxPlat();
#endif
}

BOOLEAN
CxPlatProcessorInfoInit(
    void
    )
{
    BOOLEAN Result = FALSE;
    DWORD BufferLength = 0;
    uint8_t* Buffer = NULL;
    uint32_t Offset;

    uint32_t ActiveProcessorCount = CxPlatProcActiveCount();
    uint32_t ProcessorGroupCount = 0;
    uint32_t ProcessorsPerGroup = 0;
    uint32_t NumaNodeCount = 0;

    CxPlatProcessorInfo = CXPLAT_ALLOC_NONPAGED(ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO));
    if (CxPlatProcessorInfo == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatProcessorInfo",
            ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO));
        goto Error;
    }

    GetLogicalProcessorInformationEx(RelationAll, NULL, &BufferLength);
    if (BufferLength == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX size");
        goto Error;
    }

    Buffer = CXPLAT_ALLOC_NONPAGED(BufferLength);
    if (Buffer == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX",
            BufferLength);
        goto Error;
    }

    if (!GetLogicalProcessorInformationEx(
            RelationAll,
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
            &BufferLength)) {
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "GetLogicalProcessorInformationEx failed");
        goto Error;
    }

    Offset = 0;
    while (Offset < BufferLength) {
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        if (Info->Relationship == RelationNumaNode) {
            if (Info->NumaNode.NodeNumber + 1 > NumaNodeCount) {
                NumaNodeCount = Info->NumaNode.NodeNumber + 1;
            }
        } else if (Info->Relationship == RelationGroup) {
            if (ProcessorGroupCount == 0) {
                CXPLAT_DBG_ASSERT(Info->Group.ActiveGroupCount != 0);
                ProcessorGroupCount = Info->Group.ActiveGroupCount;
                ProcessorsPerGroup = Info->Group.GroupInfo[0].ActiveProcessorCount;
            }
        }
        Offset += Info->Size;
    }

    CXPLAT_DBG_ASSERT(ProcessorGroupCount != 0);
    if (ProcessorGroupCount == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group count");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(ProcessorsPerGroup != 0);
    if (ProcessorsPerGroup == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processors per group count");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(NumaNodeCount != 0);
    if (NumaNodeCount == 0) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node count");
        goto Error;
    }

    CxPlatProcessorGroupOffsets = CXPLAT_ALLOC_NONPAGED(ProcessorGroupCount * sizeof(uint32_t));
    if (CxPlatProcessorGroupOffsets == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatProcessorGroupOffsets",
            ProcessorGroupCount * sizeof(uint32_t));
        goto Error;
    }

    for (uint32_t i = 0; i < ProcessorGroupCount; ++i) {
        CxPlatProcessorGroupOffsets[i] = i * ProcessorsPerGroup;
    }

    CxPlatNumaMasks = CXPLAT_ALLOC_NONPAGED(NumaNodeCount * sizeof(uint64_t));
    if (CxPlatNumaMasks == NULL) {
        CxPlatTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatNumaMasks",
            NumaNodeCount * sizeof(uint64_t));
        goto Error;
    }

    CxPlatTraceLogInfo(
        WindowsUserProcessorState,
        "[ dll] Processors:%u, Groups:%u, NUMA Nodes:%u",
        ActiveProcessorCount, ProcessorGroupCount, NumaNodeCount);

    Offset = 0;
    while (Offset < BufferLength) {
        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        if (Info->Relationship == RelationNumaNode) {
            CxPlatNumaMasks[Info->NumaNode.NodeNumber] = (uint64_t)Info->NumaNode.GroupMask.Mask;
        }
        Offset += Info->Size;
    }

    for (uint32_t Index = 0; Index < ActiveProcessorCount; ++Index) {

        Offset = 0;
        while (Offset < BufferLength) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
            if (Info->Relationship == RelationGroup) {
                uint32_t ProcessorOffset = 0;
                for (WORD i = 0; i < Info->Group.ActiveGroupCount; ++i) {
                    uint32_t IndexToSet = Index - ProcessorOffset;
                    if (IndexToSet < Info->Group.GroupInfo[i].ActiveProcessorCount) {
                        CXPLAT_DBG_ASSERT(IndexToSet < 64);
                        CxPlatProcessorInfo[Index].Group = i;
                        CxPlatProcessorInfo[Index].Index = IndexToSet;
                        CxPlatProcessorInfo[Index].MaskInGroup = 1ull << IndexToSet;
                        goto FindNumaNode;
                    }
                    ProcessorOffset += Info->Group.GroupInfo[i].ActiveProcessorCount;
                }
            }
            Offset += Info->Size;
        }

        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group");
        goto Error;

FindNumaNode:

        Offset = 0;
        while (Offset < BufferLength) {
            PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info =
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
            if (Info->Relationship == RelationNumaNode) {
                if (Info->NumaNode.GroupMask.Group == CxPlatProcessorInfo[Index].Group &&
                    (Info->NumaNode.GroupMask.Mask & CxPlatProcessorInfo[Index].MaskInGroup) != 0) {
                    CxPlatProcessorInfo[Index].NumaNode = Info->NumaNode.NodeNumber;
                    CxPlatTraceLogInfo(
                        ProcessorInfo,
                        "[ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]",
                        Index,
                        CxPlatProcessorInfo[Index].Group,
                        CxPlatProcessorInfo[Index].Index,
                        CxPlatProcessorInfo[Index].NumaNode);
                    goto Next;
                }
            }
            Offset += Info->Size;
        }

        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node");
        goto Error;

Next:
        ;
    }

    Result = TRUE;

Error:

    CXPLAT_FREE(Buffer);

    if (!Result) {
        CXPLAT_FREE(CxPlatNumaMasks);
        CxPlatNumaMasks = NULL;
        CXPLAT_FREE(CxPlatProcessorGroupOffsets);
        CxPlatProcessorGroupOffsets = NULL;
        CXPLAT_FREE(CxPlatProcessorInfo);
        CxPlatProcessorInfo = NULL;
    }

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
CxPlatPlatformInitialize(
    void
    )
{
    CXPLAT_STATUS Status;
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);

    CxPlatPlatform.Heap = HeapCreate(0, 0, 0);
    if (CxPlatPlatform.Heap == NULL) {
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (!CxPlatProcessorInfoInit()) {
        CxPlatTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CxPlatProcessorInfoInit failed");
        Status = CXPLAT_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    if (!GlobalMemoryStatusEx(&memInfo)) {
        DWORD Error = GetLastError();
        CxPlatTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GlobalMemoryStatusEx failed");
        Status = HRESULT_FROM_WIN32(Error);
        goto Error;
    }

    Status = CxPlatTlsLibraryInitialize();
    if (CXPLAT_FAILED(Status)) {
        goto Error;
    }

    CxPlatTotalMemory = memInfo.ullTotalPageFile;

    CxPlatTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        CxPlatTotalMemory);

Error:

    if (CXPLAT_FAILED(Status)) {
        if (CxPlatPlatform.Heap) {
            HeapDestroy(CxPlatPlatform.Heap);
            CxPlatPlatform.Heap = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformUninitialize(
    void
    )
{
    CxPlatTlsLibraryUninitialize();
    CXPLAT_DBG_ASSERT(CxPlatPlatform.Heap);
    CXPLAT_FREE(CxPlatNumaMasks);
    CxPlatNumaMasks = NULL;
    CXPLAT_FREE(CxPlatProcessorGroupOffsets);
    CxPlatProcessorGroupOffsets = NULL;
    CXPLAT_FREE(CxPlatProcessorInfo);
    CxPlatProcessorInfo = NULL;
    HeapDestroy(CxPlatPlatform.Heap);
    CxPlatPlatform.Heap = NULL;
    CxPlatTraceLogInfo(
        WindowsUserUninitialized,
        "[ dll] Uninitialized");
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

#ifdef CXPLAT_FUZZER
//
// When fuzzing we want predictable random numbers
// so that when injection / mutating traffic, variances in
// things like connection ID and random values do not
// invalidate the saved fuzzer inputs.
//
uint8_t CXPLAT_FUZZ_RND_IDX = 0;

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    memset(Buffer, ++CXPLAT_FUZZ_RND_IDX, BufferLen);
    return 0;
}

#else

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    )
{
    //
    // Just use the system-preferred random number generator algorithm.
    //
    return (CXPLAT_STATUS)
        BCryptGenRandom(
            NULL,
            (uint8_t*)Buffer,
            BufferLen,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

#endif

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
void*
CxPlatAlloc(
    _In_ size_t ByteCount
    )
{
    CXPLAT_DBG_ASSERT(CxPlatPlatform.Heap);
#ifdef CXPLAT_RANDOM_ALLOC_FAIL
    uint8_t Rand; CxPlatRandom(sizeof(Rand), &Rand);
    return ((Rand % 100) == 1) ? NULL : HeapAlloc(CxPlatPlatform.Heap, 0, ByteCount);
#else
    return HeapAlloc(CxPlatPlatform.Heap, 0, ByteCount);
#endif // CXPLAT_RANDOM_ALLOC_FAIL
}

void
CxPlatFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    )
{
    (void)HeapFree(CxPlatPlatform.Heap, 0, Mem);
}

__declspec(noreturn)
void
KrmlExit(
    int n
    )
{
    UNREFERENCED_PARAMETER(n);
    CXPLAT_FRE_ASSERTMSG(FALSE, "miTLS hit a fatal error");
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
