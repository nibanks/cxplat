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

#define CxPlatTraceEventEnabled(Name) TRUE //EventEnabledCxPlat##Name()

#define CLOG_BYTEARRAY(Len, Data) (uint8_t)(Len), (uint8_t*)(Data)
