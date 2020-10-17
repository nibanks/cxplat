/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    C++ Declarations for the CxPlat API, which enables applications and
    drivers to create QUIC connections as a client or server.

    For more detailed information, see ../docs/API.md

Supported Platforms:

    Windows User mode
    Windows Kernel mode
    Linux User mode

--*/

#pragma once

#include <cxplat.h>

#ifndef CXPLAT_DBG_ASSERT
#define CXPLAT_DBG_ASSERT(X) // no-op if not already defined
#endif

struct CxPlatAddr {
    CXPLAT_ADDR SockAddr;
    CxPlatAddr() {
        memset(&SockAddr, 0, sizeof(SockAddr));
    }
    CxPlatAddr(CXPLAT_ADDRESS_FAMILY af) {
        memset(&SockAddr, 0, sizeof(SockAddr));
        CxPlatAddrSetFamily(&SockAddr, af);
    }
    CxPlatAddr(CXPLAT_ADDRESS_FAMILY af, uint16_t Port) {
        memset(&SockAddr, 0, sizeof(SockAddr));
        CxPlatAddrSetFamily(&SockAddr, af);
        CxPlatAddrSetPort(&SockAddr, Port);
    }
    CxPlatAddr(CXPLAT_ADDRESS_FAMILY af, bool /*unused*/) {
        memset(&SockAddr, 0, sizeof(SockAddr));
        CxPlatAddrSetFamily(&SockAddr, af);
        CxPlatAddrSetToLoopback(&SockAddr);
    }
    CxPlatAddr(const CxPlatAddr &Addr, uint16_t Port) {
        SockAddr = Addr.SockAddr;
        CxPlatAddrSetPort(&SockAddr, Port);
    }
    void IncrementPort() {
        CXPLAT_DBG_ASSERT(CxPlatAddrGetPort(&SockAddr) != 0xFFFF);
        CxPlatAddrSetPort(&SockAddr, (uint16_t)1 + CxPlatAddrGetPort(&SockAddr));
    }
    void IncrementAddr() {
        CxPlatAddrIncrement(&SockAddr);
    }
    uint16_t GetPort() const { return CxPlatAddrGetPort(&SockAddr); }
    void SetPort(uint16_t Port) noexcept { CxPlatAddrSetPort(&SockAddr, Port); }
};

template<class T>
class UniquePtr {
public:
    UniquePtr() noexcept = default;

    explicit UniquePtr(T* _ptr) : ptr{_ptr} { }
    UniquePtr(const UniquePtr& other) = delete;
    UniquePtr& operator=(const UniquePtr& other) = delete;

    UniquePtr(UniquePtr&& other) noexcept {
        this->ptr = other.ptr;
        other.ptr = nullptr;
    }

    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
        this->ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
    }

    ~UniquePtr() noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
    }

    void reset(T* lptr) noexcept {
        if (this->ptr) {
            delete this->ptr;
        }
        this->ptr = lptr;
    }

    T* release() noexcept {
        T* tmp = ptr;
        ptr = nullptr;
        return tmp;
    }

    T* get() const noexcept { return ptr; }

    T& operator*() const { return *ptr; }
    T* operator->() const noexcept { return ptr; }
    operator bool() const noexcept { return ptr != nullptr; }
    bool operator == (T* _ptr) const noexcept { return ptr == _ptr; }
    bool operator != (T* _ptr) const noexcept { return ptr != _ptr; }

private:
    T* ptr = nullptr;
};

template<typename T>
class UniquePtr<T[]> {
public:
    UniquePtr() noexcept = default;

    explicit UniquePtr(T* _ptr) : ptr{_ptr} { }

    UniquePtr(const UniquePtr& other) = delete;
    UniquePtr& operator=(const UniquePtr& other) = delete;

    UniquePtr(UniquePtr&& other) noexcept {
        this->ptr = other.ptr;
        other.ptr = nullptr;
    }

    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
    }

    ~UniquePtr() noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
    }

    void reset(T* _ptr) noexcept {
        if (this->ptr) {
            delete[] this->ptr;
        }
        this->ptr = _ptr;
    }

    T* release() noexcept {
        T* tmp = ptr;
        ptr = nullptr;
        return tmp;
    }

    T* get() const noexcept { return ptr; }

    T& operator[](size_t i) const {
        return *(ptr + i);
    }

    operator bool() const noexcept { return ptr != nullptr; }
    bool operator == (T* _ptr) const noexcept { return ptr == _ptr; }
    bool operator != (T* _ptr) const noexcept { return ptr != _ptr; }

private:
    T* ptr = nullptr;
};

template<class T>
class UniquePtrArray {
    T* ptr;
public:
    UniquePtrArray() : ptr(nullptr) { }
    UniquePtrArray(T* _ptr) : ptr(_ptr) { }
    ~UniquePtrArray() { delete [] ptr; }
    T* get() { return ptr; }
    const T* get() const { return ptr; }
    T& operator*() const { return *ptr; }
    T* operator->() const { return ptr; }
    operator bool() const { return ptr != nullptr; }
    bool operator == (T* _ptr) const { return ptr == _ptr; }
    bool operator != (T* _ptr) const { return ptr != _ptr; }
};

class CxPlatApi : public CXPLAT_API_TABLE {
    const CXPLAT_API_TABLE* ApiTable {nullptr};
    CXPLAT_STATUS InitStatus;
public:
    CxPlatApi() noexcept {
        if (CXPLAT_SUCCEEDED(InitStatus = CxPlatOpen(&ApiTable))) {
            CXPLAT_API_TABLE* thisTable = this;
            memcpy(thisTable, ApiTable, sizeof(*ApiTable));
        }
    }
    ~CxPlatApi() noexcept {
        if (CXPLAT_SUCCEEDED(InitStatus)) {
            CxPlatClose(ApiTable);
            ApiTable = nullptr;
            CXPLAT_API_TABLE* thisTable = this;
            memset(thisTable, 0, sizeof(*thisTable));
        }
    }
    CXPLAT_STATUS GetInitStatus() const noexcept { return InitStatus; }
};

extern const CxPlatApi* CxPlat;

class CxPlatRegistration {
    bool CloseAllConnectionsOnDelete {false};
    HQUIC Handle {nullptr};
    CXPLAT_STATUS InitStatus;
public:
    operator HQUIC () const noexcept { return Handle; }
    CxPlatRegistration(
        _In_ bool AutoCleanUp = false
        ) noexcept : CloseAllConnectionsOnDelete(AutoCleanUp) {
        InitStatus = CxPlat->RegistrationOpen(nullptr, &Handle);
    }
    CxPlatRegistration(
        _In_z_ const char* AppName,
        CXPLAT_EXECUTION_PROFILE Profile = CXPLAT_EXECUTION_PROFILE_LOW_LATENCY,
        _In_ bool AutoCleanUp = false
        ) noexcept : CloseAllConnectionsOnDelete(AutoCleanUp) {
        const CXPLAT_REGISTRATION_CONFIG RegConfig = { AppName, Profile };
        InitStatus = CxPlat->RegistrationOpen(&RegConfig, &Handle);
    }
    ~CxPlatRegistration() noexcept {
        if (Handle != nullptr) {
            if (CloseAllConnectionsOnDelete) {
                CxPlat->RegistrationShutdown(
                    Handle,
                    CXPLAT_CONNECTION_SHUTDOWN_FLAG_SILENT,
                    1);
            }
            CxPlat->RegistrationClose(Handle);
        }
    }
    CXPLAT_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept { return CXPLAT_SUCCEEDED(InitStatus); }
    CxPlatRegistration(CxPlatRegistration& other) = delete;
    CxPlatRegistration operator=(CxPlatRegistration& Other) = delete;
    void Shutdown(
        _In_ CXPLAT_CONNECTION_SHUTDOWN_FLAGS Flags,
        _In_ CXPLAT_UINT62 ErrorCode
        ) noexcept {
        CxPlat->RegistrationShutdown(Handle, Flags, ErrorCode);
    }
};

class CxPlatAlpn {
    CXPLAT_BUFFER Buffers[2];
    uint32_t BuffersLength;
public:
    CxPlatAlpn(_In_z_ const char* RawAlpn1) noexcept {
        Buffers[0].Buffer = (uint8_t*)RawAlpn1;
        Buffers[0].Length = (uint32_t)strlen(RawAlpn1);
        BuffersLength = 1;
    }
    CxPlatAlpn(_In_z_ const char* RawAlpn1, _In_z_ const char* RawAlpn2) noexcept {
        Buffers[0].Buffer = (uint8_t*)RawAlpn1;
        Buffers[0].Length = (uint32_t)strlen(RawAlpn1);
        Buffers[1].Buffer = (uint8_t*)RawAlpn2;
        Buffers[1].Length = (uint32_t)strlen(RawAlpn2);
        BuffersLength = 2;
    }
    operator const CXPLAT_BUFFER* () const noexcept { return Buffers; }
    uint32_t Length() const noexcept { return BuffersLength; }
};

class CxPlatSettings : public CXPLAT_SETTINGS {
public:
    CxPlatSettings() noexcept { IsSetFlags = 0; }
    CxPlatSettings& SetSendBufferingEnabled(bool Value) { SendBufferingEnabled = Value; IsSet.SendBufferingEnabled = TRUE; return *this; }
    CxPlatSettings& SetPacingEnabled(bool Value) { PacingEnabled = Value; IsSet.PacingEnabled = TRUE; return *this; }
    CxPlatSettings& SetMigrationEnabled(bool Value) { MigrationEnabled = Value; IsSet.MigrationEnabled = TRUE; return *this; }
    CxPlatSettings& SetDatagramReceiveEnabled(bool Value) { DatagramReceiveEnabled = Value; IsSet.DatagramReceiveEnabled = TRUE; return *this; }
    CxPlatSettings& SetServerResumptionLevel(CXPLAT_SERVER_RESUMPTION_LEVEL Value) { ServerResumptionLevel = Value; IsSet.ServerResumptionLevel = TRUE; return *this; }
    CxPlatSettings& SetIdleTimeoutMs(uint64_t Value) { IdleTimeoutMs = Value; IsSet.IdleTimeoutMs = TRUE; return *this; }
    CxPlatSettings& SetHandshakeIdleTimeoutMs(uint64_t Value) { HandshakeIdleTimeoutMs = Value; IsSet.HandshakeIdleTimeoutMs = TRUE; return *this; }
    CxPlatSettings& SetDisconnectTimeoutMs(uint32_t Value) { DisconnectTimeoutMs = Value; IsSet.DisconnectTimeoutMs = TRUE; return *this; }
    CxPlatSettings& SetPeerBidiStreamCount(uint16_t Value) { PeerBidiStreamCount = Value; IsSet.PeerBidiStreamCount = TRUE; return *this; }
    CxPlatSettings& SetPeerUnidiStreamCount(uint16_t Value) { PeerUnidiStreamCount = Value; IsSet.PeerUnidiStreamCount = TRUE; return *this; }
    CxPlatSettings& SetMaxBytesPerKey(uint64_t Value) { MaxBytesPerKey = Value; IsSet.MaxBytesPerKey = TRUE; return *this; }
    CxPlatSettings& SetMaxAckDelayMs(uint32_t Value) { MaxAckDelayMs = Value; IsSet.MaxAckDelayMs = TRUE; return *this; }
};

#ifndef CXPLAT_DEFAULT_CLIENT_CRED_FLAGS
#define CXPLAT_DEFAULT_CLIENT_CRED_FLAGS CXPLAT_CREDENTIAL_FLAG_CLIENT
#endif

class CxPlatCredentialConfig : public CXPLAT_CREDENTIAL_CONFIG {
public:
    CxPlatCredentialConfig(const CXPLAT_CREDENTIAL_CONFIG& Config) {
        CXPLAT_CREDENTIAL_CONFIG* thisStruct = this;
        memcpy(thisStruct, &Config, sizeof(CXPLAT_CREDENTIAL_CONFIG));
    }
    CxPlatCredentialConfig(CXPLAT_CREDENTIAL_FLAGS _Flags = CXPLAT_DEFAULT_CLIENT_CRED_FLAGS) {
        CXPLAT_CREDENTIAL_CONFIG* thisStruct = this;
        memset(thisStruct, 0, sizeof(CXPLAT_CREDENTIAL_CONFIG));
        Flags = _Flags;
    }
};

class CxPlatConfiguration {
    HQUIC Handle {nullptr};
    CXPLAT_STATUS InitStatus;
public:
    operator HQUIC () const noexcept { return Handle; }
    CxPlatConfiguration(
        _In_ const CxPlatRegistration& Reg,
        _In_ const CxPlatAlpn& Alpns
        )  {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            CxPlat->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                nullptr,
                0,
                nullptr,
                &Handle);
    }
    CxPlatConfiguration(
        _In_ const CxPlatRegistration& Reg,
        _In_ const CxPlatAlpn& Alpns,
        _In_ const CxPlatCredentialConfig& CredConfig
        )  {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            CxPlat->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                nullptr,
                0,
                nullptr,
                &Handle);
        if (IsValid()) {
            InitStatus = LoadCredential(&CredConfig);
        }
    }
    CxPlatConfiguration(
        _In_ const CxPlatRegistration& Reg,
        _In_ const CxPlatAlpn& Alpns,
        _In_ const CxPlatSettings& Settings
        ) noexcept {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            CxPlat->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                &Settings,
                sizeof(Settings),
                nullptr,
                &Handle);
    }
    CxPlatConfiguration(
        _In_ const CxPlatRegistration& Reg,
        _In_ const CxPlatAlpn& Alpns,
        _In_ const CxPlatSettings& Settings,
        _In_ const CxPlatCredentialConfig& CredConfig
        ) noexcept {
        InitStatus = !Reg.IsValid() ?
            Reg.GetInitStatus() :
            CxPlat->ConfigurationOpen(
                Reg,
                Alpns,
                Alpns.Length(),
                &Settings,
                sizeof(Settings),
                nullptr,
                &Handle);
        if (IsValid()) {
            InitStatus = LoadCredential(&CredConfig);
        }
    }
    ~CxPlatConfiguration() noexcept {
        if (Handle != nullptr) {
            CxPlat->ConfigurationClose(Handle);
        }
    }
    CXPLAT_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const noexcept { return CXPLAT_SUCCEEDED(InitStatus); }
    CxPlatConfiguration(CxPlatConfiguration& other) = delete;
    CxPlatConfiguration operator=(CxPlatConfiguration& Other) = delete;
    CXPLAT_STATUS
    LoadCredential(_In_ const CXPLAT_CREDENTIAL_CONFIG* CredConfig) noexcept {
        return CxPlat->ConfigurationLoadCredential(Handle, CredConfig);
    }
};

struct CxPlatListener {
    HQUIC Handle { nullptr };
    CXPLAT_STATUS InitStatus;
    CXPLAT_LISTENER_CALLBACK_HANDLER Handler { nullptr };
    void* Context{ nullptr };

    CxPlatListener(const CxPlatRegistration& Registration) noexcept {
        if (!Registration.IsValid()) {
            InitStatus = Registration.GetInitStatus();
            return;
        }
        if (CXPLAT_FAILED(
            InitStatus =
                CxPlat->ListenerOpen(
                    Registration,
                    [](HQUIC Handle, void* Context, CXPLAT_LISTENER_EVENT* Event) -> CXPLAT_STATUS {
                        CxPlatListener* Listener = (CxPlatListener*)Context;
                        return Listener->Handler(Handle, Listener->Context, Event);
                    },
                    this,
                    &Handle))) {
            Handle = nullptr;
        }
    }
    ~CxPlatListener() noexcept {
        if (Handler != nullptr) {
            CxPlat->ListenerStop(Handle);
        }
        if (Handle) {
            CxPlat->ListenerClose(Handle);
        }
    }

    CXPLAT_STATUS
    Start(
        _In_ const CxPlatAlpn& Alpns,
        _In_ CXPLAT_ADDR* Address,
        _In_ CXPLAT_LISTENER_CALLBACK_HANDLER _Handler,
        _In_ void* _Context) noexcept {
        Handler = _Handler;
        Context = _Context;
        return CxPlat->ListenerStart(Handle, Alpns, Alpns.Length(), Address);
    }

    CXPLAT_STATUS
    ListenerCallback(HQUIC Listener, CXPLAT_LISTENER_EVENT* Event) noexcept {
        return Handler(Listener, Context, Event);
    }

    CXPLAT_STATUS GetInitStatus() const noexcept { return InitStatus; }
    bool IsValid() const { return CXPLAT_SUCCEEDED(InitStatus); }
    CxPlatListener(CxPlatListener& other) = delete;
    CxPlatListener operator=(CxPlatListener& Other) = delete;
    operator HQUIC () const noexcept { return Handle; }
};

struct ListenerScope {
    HQUIC Handle;
    ListenerScope() noexcept : Handle(nullptr) { }
    ListenerScope(HQUIC handle) noexcept : Handle(handle) { }
    ~ListenerScope() noexcept { if (Handle) { CxPlat->ListenerClose(Handle); } }
    operator HQUIC() const noexcept { return Handle; }
};

struct ConnectionScope {
    HQUIC Handle;
    ConnectionScope() noexcept : Handle(nullptr) { }
    ConnectionScope(HQUIC handle) noexcept : Handle(handle) { }
    ~ConnectionScope() noexcept { if (Handle) { CxPlat->ConnectionClose(Handle); } }
    operator HQUIC() const noexcept { return Handle; }
};

struct StreamScope {
    HQUIC Handle;
    StreamScope() noexcept : Handle(nullptr) { }
    StreamScope(HQUIC handle) noexcept : Handle(handle) { }
    ~StreamScope() noexcept { if (Handle) { CxPlat->StreamClose(Handle); } }
    operator HQUIC() const noexcept { return Handle; }
};

struct CxPlatBufferScope {
    CXPLAT_BUFFER* Buffer;
    CxPlatBufferScope() noexcept : Buffer(nullptr) { }
    CxPlatBufferScope(uint32_t Size) noexcept : Buffer((CXPLAT_BUFFER*) new uint8_t[sizeof(CXPLAT_BUFFER) + Size]) {
        memset(Buffer, 0, sizeof(*Buffer) + Size);
        Buffer->Length = Size;
        Buffer->Buffer = (uint8_t*)(Buffer + 1);
    }
    operator CXPLAT_BUFFER* () noexcept { return Buffer; }
    ~CxPlatBufferScope() noexcept { if (Buffer) { delete[](uint8_t*) Buffer; } }
};

#ifdef CXPLAT_PLATFORM_TYPE

//
// Abstractions for platform specific types/interfaces
//

struct EventScope {
    CXPLAT_EVENT Handle;
    EventScope() noexcept { CxPlatEventInitialize(&Handle, FALSE, FALSE); }
    EventScope(bool ManualReset) noexcept { CxPlatEventInitialize(&Handle, ManualReset, FALSE); }
    EventScope(CXPLAT_EVENT event) noexcept : Handle(event) { }
    ~EventScope() noexcept { CxPlatEventUninitialize(Handle); }
    operator CXPLAT_EVENT() const noexcept { return Handle; }
};

#endif
