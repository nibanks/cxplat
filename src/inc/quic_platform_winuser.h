/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains Windows User Mode implementations of the
    QUIC Platform Interfaces.

Environment:

    Windows user mode

--*/

#pragma once

#ifndef CXPLAT_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifdef _KERNEL_MODE
#error "Incorrectly including Windows User Platform Header"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#ifdef CXPLAT_UWP_BUILD
#undef WINAPI_FAMILY
#define WINAPI_FAMILY WINAPI_FAMILY_DESKTOP_APP
#endif

#pragma warning(push) // Don't care about OACR warnings in publics
#pragma warning(disable:26036)
#pragma warning(disable:28252)
#pragma warning(disable:28253)
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <winternl.h>
#ifdef _M_X64
#include <intrin.h>
#endif
#ifdef CXPLAT_TELEMETRY_ASSERTS
#include <telemetry\MicrosoftTelemetryAssert.h>
#endif
#include <cxplat_winuser.h>
#pragma warning(pop)

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4324)  // 'CXPLAT_POOL': structure was padded due to alignment specifier

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(DEBUG) || defined(_DEBUG)
#define DBG 1
#define DEBUG 1
#endif

#if _WIN64
#define CXPLAT_64BIT 1
#else
#define CXPLAT_32BIT 1
#endif

#define INITCODE
#define PAGEDX

#define CXPLAT_CACHEALIGN DECLSPEC_CACHEALIGN

#define ALIGN_DOWN(length, type) \
    ((ULONG)(length) & ~(sizeof(type) - 1))

#define ALIGN_UP(length, type) \
    (ALIGN_DOWN(((ULONG)(length) + sizeof(type) - 1), type))

//
// Library Initialization
//

//
// Called in DLLMain or DriverEntry.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformSystemLoad(
    void
    );

//
// Called in DLLMain or DriverUnload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformSystemUnload(
    void
    );

//
// Initializes the PAL library. Calls to this and
// CxPlatPlatformUninitialize must be serialized and cannot overlap.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_STATUS
CxPlatPlatformInitialize(
    void
    );

//
// Uninitializes the PAL library. Calls to this and
// CxPlatPlatformInitialize must be serialized and cannot overlap.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatformUninitialize(
    void
    );

//
// Assertion Interfaces
//

#define CXPLAT_STATIC_ASSERT(X,Y) static_assert(X,Y)

#define CXPLAT_ANALYSIS_ASSERT(X) __analysis_assert(X)

//
// Logs the assertion failure to ETW.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    );

#define CXPLAT_ASSERT_ACTION(_exp) \
    ((!(_exp)) ? \
        (CxPlatPlatformLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", L#_exp), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define CXPLAT_ASSERTMSG_ACTION(_msg, _exp) \
    ((!(_exp)) ? \
        (CxPlatPlatformLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", L##_msg), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#if defined(_PREFAST_)
// _Analysis_assume_ will never result in any code generation for _exp,
// so using it will not have runtime impact, even if _exp has side effects.
#define CXPLAT_ANALYSIS_ASSUME(_exp) _Analysis_assume_(_exp)
#else // _PREFAST_
// CXPLAT_ANALYSIS_ASSUME ensures that _exp is parsed in non-analysis compile.
// On DEBUG, it's guaranteed to be parsed as part of the normal compile, but
// with non-DEBUG, use __noop to ensure _exp is parseable but without code
// generation.
#if DEBUG
#define CXPLAT_ANALYSIS_ASSUME(_exp) ((void) 0)
#else // DEBUG
#define CXPLAT_ANALYSIS_ASSUME(_exp) __noop(_exp)
#endif // DEBUG
#endif // _PREFAST_

#define CXPLAT_NO_SANITIZE(X)


//
// CxPlat uses three types of asserts:
//
//  CXPLAT_DBG_ASSERT - Asserts that are too expensive to evaluate all the time.
//  CXPLAT_TEL_ASSERT - Asserts that are acceptable to always evaluate, but not
//                    always crash the process.
//  CXPLAT_FRE_ASSERT - Asserts that must always crash the process.
//

#if DEBUG
#define CXPLAT_DBG_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERT_ACTION(_exp))
#define CXPLAT_DBG_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERTMSG_ACTION(_msg, _exp))
#else
#define CXPLAT_DBG_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#define CXPLAT_DBG_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#endif

#if DEBUG
#define CXPLAT_TEL_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERT_ACTION(_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERTMSG_ACTION(_msg, _exp))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
     (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERTMSG_ACTION(_msg, _exp))
#else
#ifdef MICROSOFT_TELEMETRY_ASSERT
#define CXPLAT_TEL_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT(_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_MSG(_exp, _msg))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_MSG_WITH_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2))
#else
#define CXPLAT_TEL_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#endif
#endif

#define CXPLAT_FRE_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERT_ACTION(_exp))
#define CXPLAT_FRE_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), CXPLAT_ASSERTMSG_ACTION(_msg, _exp))

//
// Verifier is enabled.
//
#define CxPlatVerifierEnabled(Flags) \
    (GetModuleHandleW(L"verifier.dll") != NULL && \
     GetModuleHandleW(L"vrfcore.dll") != NULL), \
    Flags = 0

//
// Debugger check.
//
#define CxPlatDebuggerPresent() IsDebuggerPresent()

//
// Interrupt ReQuest Level
//

#define CXPLAT_IRQL() PASSIVE_LEVEL

#define CXPLAT_PASSIVE_CODE() CXPLAT_DBG_ASSERT(CXPLAT_IRQL() == PASSIVE_LEVEL)

//
// Allocation/Memory Interfaces
//

extern uint64_t CxPlatTotalMemory;

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
void*
CxPlatAlloc(
    _In_ size_t ByteCount
    );

void
CxPlatFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    );

#define CXPLAT_ALLOC_PAGED(Size) CxPlatAlloc(Size)
#define CXPLAT_ALLOC_NONPAGED(Size) CxPlatAlloc(Size)
#define CXPLAT_FREE(Mem) CxPlatFree((void*)Mem)
#define CXPLAT_FREE_TAG(Mem, Tag) CXPLAT_FREE(Mem)

typedef struct CXPLAT_POOL {
    SLIST_HEADER ListHead;
    uint32_t Size;
} CXPLAT_POOL;

#define CXPLAT_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

#if DEBUG
typedef struct CXPLAT_POOL_ENTRY {
    SLIST_ENTRY ListHead;
    uint32_t SpecialFlag;
} CXPLAT_POOL_ENTRY;
#define CXPLAT_POOL_SPECIAL_FLAG    0xAAAAAAAA
#endif

inline
void
CxPlatPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(Size >= sizeof(CXPLAT_POOL_ENTRY));
#endif
    Pool->Size = Size;
    InitializeSListHead(&(Pool)->ListHead);
    UNREFERENCED_PARAMETER(IsPaged);
    UNREFERENCED_PARAMETER(Tag); // TODO - Use in debug mode?
}

inline
void
CxPlatPoolUninitialize(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    void* Entry;
    while ((Entry = InterlockedPopEntrySList(&Pool->ListHead)) != NULL) {
        CxPlatFree(Entry);
    }
}

inline
void*
CxPlatPoolAlloc(
    _Inout_ CXPLAT_POOL* Pool
    )
{
#if CXPLAT_DISABLE_MEM_POOL
    return CxPlatAlloc(Pool->Size);
#else
    void* Entry = InterlockedPopEntrySList(&Pool->ListHead);
    if (Entry == NULL) {
        Entry = CxPlatAlloc(Pool->Size);
    }
#if DEBUG
    if (Entry != NULL) {
        ((CXPLAT_POOL_ENTRY*)Entry)->SpecialFlag = 0;
    }
#endif
    return Entry;
#endif
}

inline
void
CxPlatPoolFree(
    _Inout_ CXPLAT_POOL* Pool,
    _In_ void* Entry
    )
{
#if CXPLAT_DISABLE_MEM_POOL
    UNREFERENCED_PARAMETER(Pool);
    CxPlatFree(Entry);
    return;
#else
#if DEBUG
    CXPLAT_DBG_ASSERT(((CXPLAT_POOL_ENTRY*)Entry)->SpecialFlag != CXPLAT_POOL_SPECIAL_FLAG);
    ((CXPLAT_POOL_ENTRY*)Entry)->SpecialFlag = CXPLAT_POOL_SPECIAL_FLAG;
#endif
    if (QueryDepthSList(&Pool->ListHead) >= CXPLAT_POOL_MAXIMUM_DEPTH) {
        CxPlatFree(Entry);
    } else {
        InterlockedPushEntrySList(&Pool->ListHead, (PSLIST_ENTRY)Entry);
    }
#endif
}

#define CxPlatZeroMemory RtlZeroMemory
#define CxPlatCopyMemory RtlCopyMemory
#define CxPlatMoveMemory RtlMoveMemory
#define CxPlatSecureZeroMemory RtlSecureZeroMemory

#define CxPlatByteSwapUint16 _byteswap_ushort
#define CxPlatByteSwapUint32 _byteswap_ulong
#define CxPlatByteSwapUint64 _byteswap_uint64

//
// Locking Interfaces
//

typedef CRITICAL_SECTION CXPLAT_LOCK;

#define CxPlatLockInitialize(Lock) InitializeCriticalSection(Lock)
#define CxPlatLockUninitialize(Lock) DeleteCriticalSection(Lock)
#define CxPlatLockAcquire(Lock) EnterCriticalSection(Lock)
#define CxPlatLockRelease(Lock) LeaveCriticalSection(Lock)

typedef CRITICAL_SECTION CXPLAT_DISPATCH_LOCK;

#define CxPlatDispatchLockInitialize(Lock) InitializeCriticalSection(Lock)
#define CxPlatDispatchLockUninitialize(Lock) DeleteCriticalSection(Lock)
#define CxPlatDispatchLockAcquire(Lock) EnterCriticalSection(Lock)
#define CxPlatDispatchLockRelease(Lock) LeaveCriticalSection(Lock)

typedef SRWLOCK CXPLAT_RW_LOCK;

#define CxPlatRwLockInitialize(Lock) InitializeSRWLock(Lock)
#define CxPlatRwLockUninitialize(Lock)
#define CxPlatRwLockAcquireShared(Lock) AcquireSRWLockShared(Lock)
#define CxPlatRwLockAcquireExclusive(Lock) AcquireSRWLockExclusive(Lock)
#define CxPlatRwLockReleaseShared(Lock) ReleaseSRWLockShared(Lock)
#define CxPlatRwLockReleaseExclusive(Lock) ReleaseSRWLockExclusive(Lock)

typedef SRWLOCK CXPLAT_DISPATCH_RW_LOCK;

#define CxPlatDispatchRwLockInitialize(Lock) InitializeSRWLock(Lock)
#define CxPlatDispatchRwLockUninitialize(Lock)
#define CxPlatDispatchRwLockAcquireShared(Lock) AcquireSRWLockShared(Lock)
#define CxPlatDispatchRwLockAcquireExclusive(Lock) AcquireSRWLockExclusive(Lock)
#define CxPlatDispatchRwLockReleaseShared(Lock) ReleaseSRWLockShared(Lock)
#define CxPlatDispatchRwLockReleaseExclusive(Lock) ReleaseSRWLockExclusive(Lock)

//
// Reference Count Interface
//

#if defined(_X86_) || defined(_AMD64_)
#define CxPlatBarrierAfterInterlock()
#elif defined(_ARM64_)
#define CxPlatBarrierAfterInterlock()  __dmb(_ARM64_BARRIER_ISH)
#elif defined(_ARM_)
#define CxPlatBarrierAfterInterlock()  __dmb(_ARM_BARRIER_ISH)
#else
#error Unsupported architecture.
#endif

#if defined (_WIN64)
#define CxPlatIncrementLongPtrNoFence InterlockedIncrementNoFence64
#define CxPlatDecrementLongPtrRelease InterlockedDecrementRelease64
#define CxPlatCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence64
#define CxPlatReadLongPtrNoFence ReadNoFence64
#else
#define CxPlatIncrementLongPtrNoFence InterlockedIncrementNoFence
#define CxPlatDecrementLongPtrRelease InterlockedDecrementRelease
#define CxPlatCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence
#define CxPlatReadLongPtrNoFence ReadNoFence
#endif

typedef LONG_PTR CXPLAT_REF_COUNT;

inline
void
CxPlatRefInitialize(
    _Out_ CXPLAT_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

#define CxPlatRefUninitialize(RefCount)

inline
void
CxPlatRefIncrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    )
{
    if (CxPlatIncrementLongPtrNoFence(RefCount) > 1) {
        return;
    }

    __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
}

inline
BOOLEAN
CxPlatRefIncrementNonZero(
    _Inout_ volatile CXPLAT_REF_COUNT *RefCount,
    _In_ ULONG Bias
    )
{
    CXPLAT_REF_COUNT NewValue;
    CXPLAT_REF_COUNT OldValue;

    PrefetchForWrite(RefCount);
    OldValue = CxPlatReadLongPtrNoFence(RefCount);
    for (;;) {
        NewValue = OldValue + Bias;
        if ((ULONG_PTR)NewValue > Bias) {
            NewValue = CxPlatCompareExchangeLongPtrNoFence(RefCount,
                                                         NewValue,
                                                         OldValue);
            if (NewValue == OldValue) {
                return TRUE;
            }

            OldValue = NewValue;

        } else if ((ULONG_PTR)NewValue == Bias) {
            return FALSE;

        } else {
            __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
            return FALSE;
        }
    }
}

inline
BOOLEAN
CxPlatRefDecrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    )
{
    CXPLAT_REF_COUNT NewValue;

    //
    // A release fence is required to ensure all guarded memory accesses are
    // complete before any thread can begin destroying the object.
    //

    NewValue = CxPlatDecrementLongPtrRelease(RefCount);
    if (NewValue > 0) {
        return FALSE;

    } else if (NewValue == 0) {

        //
        // An acquire fence is required before object destruction to ensure
        // that the destructor cannot observe values changing on other threads.
        //

        CxPlatBarrierAfterInterlock();
        return TRUE;
    }

    __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    return FALSE;
}

//
// Event Interfaces
//

typedef HANDLE CXPLAT_EVENT;

#define CxPlatEventInitialize(Event, ManualReset, InitialState) \
    *(Event) = CreateEvent(NULL, ManualReset, InitialState, NULL)
#define CxPlatEventUninitialize(Event) CloseHandle(Event)
#define CxPlatEventSet(Event) SetEvent(Event)
#define CxPlatEventReset(Event) ResetEvent(Event)
#define CxPlatEventWaitForever(Event) WaitForSingleObject(Event, INFINITE)
#define CxPlatEventWaitWithTimeout(Event, timeoutMs) \
    (WAIT_OBJECT_0 == WaitForSingleObject(Event, timeoutMs))

//
// Time Measurement Interfaces
//

//
// This is an undocumented API that is used to query the current timer
// resolution.
//
__kernel_entry
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryTimerResolution(
    _Out_ PULONG MaximumTime,
    _Out_ PULONG MinimumTime,
    _Out_ PULONG CurrentTime
    );

//
// Returns the worst-case system timer resolution (in us).
//
inline
uint64_t
CxPlatGetTimerResolution()
{
    ULONG MaximumTime, MinimumTime, CurrentTime;
    NtQueryTimerResolution(&MaximumTime, &MinimumTime, &CurrentTime);
    return NS100_TO_US(MaximumTime);
}

//
// Performance counter frequency.
//
extern uint64_t CxPlatPlatformPerfFreq;

//
// Returns the current time in platform specific time units.
//
inline
uint64_t
CxPlatTimePlat(
    void
    )
{
    uint64_t Count;
    QueryPerformanceCounter((LARGE_INTEGER*)&Count);
    return Count;
}

//
// Converts platform time to microseconds.
//
inline
uint64_t
CxPlatTimePlatToUs64(
    uint64_t Count
    )
{
    //
    // Multiply by a big number (1000000, to convert seconds to microseconds)
    // and divide by a big number (CxPlatPlatformPerfFreq, to convert counts to secs).
    //
    // Avoid overflow with separate multiplication/division of the high and low
    // bits. Taken from TcpConvertPerformanceCounterToMicroseconds.
    //
    uint64_t High = (Count >> 32) * 1000000;
    uint64_t Low = (Count & 0xFFFFFFFF) * 1000000;
    return
        ((High / CxPlatPlatformPerfFreq) << 32) +
        ((Low + ((High % CxPlatPlatformPerfFreq) << 32)) / CxPlatPlatformPerfFreq);
}

//
// Converts microseconds to platform time.
//
inline
uint64_t
CxPlatTimeUs64ToPlat(
    uint64_t TimeUs
    )
{
    uint64_t High = (TimeUs >> 32) * CxPlatPlatformPerfFreq;
    uint64_t Low = (TimeUs & 0xFFFFFFFF) * CxPlatPlatformPerfFreq;
    return
        ((High / 1000000) << 32) +
        ((Low + ((High % 1000000) << 32)) / CxPlatPlatformPerfFreq);
}

#define CxPlatTimeUs64() CxPlatTimePlatToUs64(CxPlatTimePlat())
#define CxPlatTimeUs32() (uint32_t)CxPlatTimeUs64()
#define CxPlatTimeMs64() US_TO_MS(CxPlatTimeUs64())
#define CxPlatTimeMs32() (uint32_t)CxPlatTimeMs64()

#define UNIX_EPOCH_AS_FILE_TIME 0x19db1ded53e8000ll

inline
int64_t
CxPlatTimeEpochMs64(
    )
{
    LARGE_INTEGER FileTime;
    GetSystemTimeAsFileTime((FILETIME*) &FileTime);
    return NS100_TO_MS(FileTime.QuadPart - UNIX_EPOCH_AS_FILE_TIME);
}

//
// Returns the difference between two timestamps.
//
inline
uint64_t
CxPlatTimeDiff64(
    _In_ uint64_t T1,     // First time measured
    _In_ uint64_t T2      // Second time measured
    )
{
    //
    // Assume no wrap around.
    //
    return T2 - T1;
}

//
// Returns the difference between two timestamps.
//
inline
uint32_t
CxPlatTimeDiff32(
    _In_ uint32_t T1,     // First time measured
    _In_ uint32_t T2      // Second time measured
    )
{
    if (T2 > T1) {
        return T2 - T1;
    } else { // Wrap around case.
        return T2 + (0xFFFFFFFF - T1) + 1;
    }
}

//
// Returns TRUE if T1 came before T2.
//
inline
BOOLEAN
CxPlatTimeAtOrBefore64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
{
    //
    // Assume no wrap around.
    //
    return T1 <= T2;
}

//
// Returns TRUE if T1 came before T2.
//
inline
BOOLEAN
CxPlatTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
{
    return (int32_t)(T1 - T2) <= 0;
}

#define CxPlatSleep(ms) Sleep(ms)

//
// Processor Count and Index
//

typedef struct {

    uint16_t Group;
    uint32_t Index; // In Group;
    uint32_t NumaNode;
    uint64_t MaskInGroup;

} CXPLAT_PROCESSOR_INFO;

extern CXPLAT_PROCESSOR_INFO* CxPlatProcessorInfo;
extern uint64_t* CxPlatNumaMasks;
extern uint32_t* CxPlatProcessorGroupOffsets;

#define CxPlatProcMaxCount() GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS)
#define CxPlatProcActiveCount() GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
CxPlatProcCurrentNumber(
    void
    ) {
    PROCESSOR_NUMBER ProcNumber;
    GetCurrentProcessorNumberEx(&ProcNumber);
    return CxPlatProcessorGroupOffsets[ProcNumber.Group] + ProcNumber.Number;
}


//
// Create Thread Interfaces
//

//
// This is the undocumented interface for setting a thread's name. This is
// essentially what SetThreadDescription does, but that is not available in
// older versions of Windows.
//
#if !defined(CXPLAT_UWP_BUILD)
#define ThreadNameInformation ((THREADINFOCLASS)38)

typedef struct _THREAD_NAME_INFORMATION {
    UNICODE_STRING ThreadName;
} THREAD_NAME_INFORMATION, *PTHREAD_NAME_INFORMATION;

__kernel_entry
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    );
#endif

typedef struct CXPLAT_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} CXPLAT_THREAD_CONFIG;

typedef HANDLE CXPLAT_THREAD;
#define CXPLAT_THREAD_CALLBACK(FuncName, CtxVarName)  \
    DWORD                                           \
    WINAPI                                          \
    FuncName(                                       \
      _In_ void* CtxVarName                         \
      )

#define CXPLAT_THREAD_RETURN(Status) return (DWORD)(Status)

inline
CXPLAT_STATUS
CxPlatThreadCreate(
    _In_ CXPLAT_THREAD_CONFIG* Config,
    _Out_ CXPLAT_THREAD* Thread
    )
{
    *Thread =
        CreateThread(
            NULL,
            0,
            Config->Callback,
            Config->Context,
            0,
            NULL);
    if (*Thread == NULL) {
        return GetLastError();
    }
    const CXPLAT_PROCESSOR_INFO* ProcInfo = &CxPlatProcessorInfo[Config->IdealProcessor];
    GROUP_AFFINITY Group = {0};
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_AFFINITIZE) {
        Group.Mask = (KAFFINITY)(1ull << ProcInfo->Index);          // Fixed processor
    } else {
        Group.Mask = (KAFFINITY)CxPlatNumaMasks[ProcInfo->NumaNode];  // Fixed NUMA node
    }
    Group.Group = ProcInfo->Group;
    SetThreadGroupAffinity(*Thread, &Group, NULL);
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_IDEAL_PROC) {
        SetThreadIdealProcessor(*Thread, ProcInfo->Index);
    }
    if (Config->Flags & CXPLAT_THREAD_FLAG_HIGH_PRIORITY) {
        SetThreadPriority(*Thread, THREAD_PRIORITY_HIGHEST);
    }
    if (Config->Name) {
        WCHAR WideName[64] = L"";
        size_t WideNameLength;
        mbstowcs_s(
            &WideNameLength,
            WideName,
            ARRAYSIZE(WideName) - 1,
            Config->Name,
            _TRUNCATE);
#if defined(CXPLAT_UWP_BUILD)
        SetThreadDescription(*Thread, WideName);
#else
        THREAD_NAME_INFORMATION ThreadNameInfo;
        RtlInitUnicodeString(&ThreadNameInfo.ThreadName, WideName);
        NtSetInformationThread(
            *Thread,
            ThreadNameInformation,
            &ThreadNameInfo,
            sizeof(ThreadNameInfo));
#endif
    }
    return CXPLAT_STATUS_SUCCESS;
}
#define CxPlatThreadDelete(Thread) CloseHandle(*(Thread))
#define CxPlatThreadWait(Thread) WaitForSingleObject(*(Thread), INFINITE)
typedef uint32_t CXPLAT_THREAD_ID;
#define CxPlatCurThreadID() GetCurrentThreadId()

//
// Rundown Protection Interfaces
//

typedef struct CXPLAT_RUNDOWN_REF {

    //
    // The ref counter.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The completion event.
    //
    HANDLE RundownComplete;

} CXPLAT_RUNDOWN_REF;

#define CxPlatRundownInitialize(Rundown) \
    CxPlatRefInitialize(&(Rundown)->RefCount); \
    (Rundown)->RundownComplete = CreateEvent(NULL, FALSE, FALSE, NULL)
#define CxPlatRundownInitializeDisabled(Rundown) \
    (Rundown)->RefCount = 0; \
    (Rundown)->RundownComplete = CreateEvent(NULL, FALSE, FALSE, NULL)
#define CxPlatRundownReInitialize(Rundown) (Rundown)->RefCount = 1
#define CxPlatRundownUninitialize(Rundown) CloseHandle((Rundown)->RundownComplete)
#define CxPlatRundownAcquire(Rundown) CxPlatRefIncrementNonZero(&(Rundown)->RefCount, 1)
#define CxPlatRundownRelease(Rundown) \
    if (CxPlatRefDecrement(&(Rundown)->RefCount)) { \
        SetEvent((Rundown)->RundownComplete); \
    }
#define CxPlatRundownReleaseAndWait(Rundown) \
    if (!CxPlatRefDecrement(&(Rundown)->RefCount)) { \
        WaitForSingleObject((Rundown)->RundownComplete, INFINITE); \
    }

//
// Crypto Interfaces
//

//
// Returns cryptographically random bytes.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

//
// Network Compartment ID interfaces
//

#ifndef CXPLAT_UWP_BUILD

#define CXPLAT_COMPARTMENT_ID NET_IF_COMPARTMENT_ID

#define CXPLAT_UNSPECIFIED_COMPARTMENT_ID NET_IF_COMPARTMENT_ID_UNSPECIFIED
#define CXPLAT_DEFAULT_COMPARTMENT_ID     NET_IF_COMPARTMENT_ID_PRIMARY

inline
CXPLAT_STATUS
CxPlatSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
    const CXPLAT_PROCESSOR_INFO* ProcInfo = &CxPlatProcessorInfo[ProcessorIndex];
    GROUP_AFFINITY Group = {0};
    Group.Mask = (KAFFINITY)(1ull << ProcInfo->Index);
    Group.Group = ProcInfo->Group;
    if (SetThreadGroupAffinity(GetCurrentThread(), &Group, NULL)) {
        return CXPLAT_STATUS_SUCCESS;
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

#define CxPlatCompartmentIdGetCurrent() GetCurrentThreadCompartmentId()
#define CxPlatCompartmentIdSetCurrent(CompartmentId) \
    HRESULT_FROM_WIN32(SetCurrentThreadCompartmentId(CompartmentId))

inline
CXPLAT_STATUS
CxPlatSetCurrentThreadGroupAffinity(
    _In_ uint16_t ProcessorGroup
    )
{
    GROUP_AFFINITY Group = {0};
    GROUP_AFFINITY ExistingGroup = {0};
    if (!GetThreadGroupAffinity(GetCurrentThread(), &ExistingGroup)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    Group.Mask = ExistingGroup.Mask;
    Group.Group = ProcessorGroup;
    if (SetThreadGroupAffinity(GetCurrentThread(), &Group, NULL)) {
        return CXPLAT_STATUS_SUCCESS;
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

#else

inline
CXPLAT_STATUS
CxPlatSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
    UNREFERENCED_PARAMETER(ProcessorIndex);
    return CXPLAT_STATUS_SUCCESS;
}

inline
CXPLAT_STATUS
CxPlatSetCurrentThreadGroupAffinity(
    _In_ uint16_t ProcessorGroup
    )
{
    UNREFERENCED_PARAMETER(ProcessorGroup);
    return CXPLAT_STATUS_SUCCESS;
}

#endif

#ifdef _M_X64
#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, edx) \
    int CpuInfo[4]; \
    CpuInfo[0] = eax; \
    CpuInfo[1] = ebx; \
    CpuInfo[2] = ecx; \
    CpuInfo[3] = edx; \
    __cpuid(CpuInfo, FunctionId);
#else
#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, dx)
#endif

#if defined(__cplusplus)
}
#endif
