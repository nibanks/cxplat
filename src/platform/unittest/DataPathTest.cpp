/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath User Mode Unit test

--*/

#include "main.h"
#include "quic_datapath.h"

#include "cxplat.h"
#ifdef CXPLAT_CLOG
#include "DataPathTest.cpp.clog.h"
#endif

const uint32_t ExpectedDataSize = 1 * 1024;
char* ExpectedData;

//
// Helper class for managing the memory of a IP address.
//
struct CxPlatAddr
{
    CXPLAT_ADDR SockAddr;

    uint16_t Port() {
        if (CxPlatAddrGetFamily(&SockAddr) == CXPLAT_ADDRESS_FAMILY_INET) {
            return SockAddr.Ipv4.sin_port;
        } else {
            return SockAddr.Ipv6.sin6_port;
        }
    }

    #undef SetPort
    void SetPort(uint16_t port) {
        if (CxPlatAddrGetFamily(&SockAddr) == CXPLAT_ADDRESS_FAMILY_INET) {
            SockAddr.Ipv4.sin_port = port;
        } else {
            SockAddr.Ipv6.sin6_port = port;
        }
    }

    CxPlatAddr() {
        CxPlatZeroMemory(this, sizeof(*this));
    }

    void Resolve(CXPLAT_ADDRESS_FAMILY af, const char* hostname) {
        CXPLAT_DATAPATH* Datapath = nullptr;
        if (CXPLAT_FAILED(
            CxPlatDataPathInitialize(
                0,
                (CXPLAT_DATAPATH_RECEIVE_CALLBACK_HANDLER)(1),
                (CXPLAT_DATAPATH_UNREACHABLE_CALLBACK_HANDLER)(1),
                &Datapath))) {
            GTEST_FATAL_FAILURE_(" CxPlatDataPathInitialize failed.");
        }
        if (CXPLAT_FAILED(
            CxPlatDataPathResolveAddress(
                Datapath,
                hostname,
                &SockAddr))) {
            GTEST_FATAL_FAILURE_("Failed to resolve IP address.");
        }
        CxPlatDataPathUninitialize(Datapath);
    }
};

struct DataRecvContext {
    CXPLAT_ADDR ServerAddress;
    CXPLAT_EVENT ClientCompletion;
};

struct DataPathTest : public ::testing::TestWithParam<int32_t>
{
protected:
    static volatile uint16_t NextPort;
    static CxPlatAddr LocalIPv4;
    static CxPlatAddr LocalIPv6;

    //
    // Helper to get a new port to bind to.
    //
    uint16_t
    GetNextPort()
    {
        return CxPlatNetByteSwapShort((uint16_t)InterlockedIncrement16((volatile short*)&NextPort));
    }

    //
    // Helper to return a new local IPv4 address and port to use.
    //
    CxPlatAddr
    GetNewLocalIPv4(bool randomPort = true)
    {
        CxPlatAddr ipv4Copy = LocalIPv4;
        if (randomPort) { ipv4Copy.SockAddr.Ipv4.sin_port = GetNextPort(); }
        else { ipv4Copy.SockAddr.Ipv4.sin_port = 0; }
        return ipv4Copy;
    }

    //
    // Helper to return a new local IPv4 address and port to use.
    //
    CxPlatAddr
    GetNewLocalIPv6(bool randomPort = true)
    {
        CxPlatAddr ipv6Copy = LocalIPv6;
        if (randomPort) { ipv6Copy.SockAddr.Ipv6.sin6_port = GetNextPort(); }
        else { ipv6Copy.SockAddr.Ipv6.sin6_port = 0; }
        return ipv6Copy;
    }

    //
    // Helper to return a new local IPv4 or IPv6 address based on the test data.
    //
    CxPlatAddr
    GetNewLocalAddr(bool randomPort = true)
    {
        int addressFamily = GetParam();

        if (addressFamily == 4) {
            return GetNewLocalIPv4(randomPort);
        } else if (addressFamily == 6) {
            return GetNewLocalIPv6(randomPort);
        } else {
            GTEST_NONFATAL_FAILURE_("Malconfigured test data; This should never happen!!");
            return CxPlatAddr();
        }
    }

    static void SetUpTestSuite()
    {
        //
        // Initialize a semi-random base port number.
        //
        NextPort = 50000 + (CxPlatCurThreadID() % 10000) + (rand() % 5000);

        LocalIPv4.Resolve(CXPLAT_ADDRESS_FAMILY_INET, "localhost");
        LocalIPv6.Resolve(CXPLAT_ADDRESS_FAMILY_INET6, "localhost");

        ExpectedData = (char*)CXPLAT_ALLOC_NONPAGED(ExpectedDataSize);
        ASSERT_NE(ExpectedData, nullptr);
    }

    static void TearDownTestSuite()
    {
        CXPLAT_FREE(ExpectedData);
    }

    static void
    EmptyReceiveCallback(
        _In_ CXPLAT_DATAPATH_BINDING* /* Binding */,
        _In_ void * /* RecvContext */,
        _In_ CXPLAT_RECV_DATAGRAM* /* RecvPacketChain */
        )
    {
    }

    static void
    EmptyUnreachableCallback(
        _In_ CXPLAT_DATAPATH_BINDING* /* Binding */,
        _In_ void * /* Context */,
        _In_ const CXPLAT_ADDR* /* RemoteAddress */
        )
    {
    }

    static void
    DataRecvCallback(
        _In_ CXPLAT_DATAPATH_BINDING* binding,
        _In_ void * recvContext,
        _In_ CXPLAT_RECV_DATAGRAM* recvBufferChain
        )
    {
        DataRecvContext* RecvContext = (DataRecvContext*)recvContext;
        ASSERT_NE(nullptr, RecvContext);

        CXPLAT_RECV_DATAGRAM* recvBuffer = recvBufferChain;

        while (recvBuffer != NULL) {
            ASSERT_EQ(recvBuffer->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(recvBuffer->Buffer, ExpectedData, ExpectedDataSize));

            if (recvBuffer->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                auto ServerSendContext =
                    CxPlatDataPathBindingAllocSendContext(binding, CXPLAT_ECN_NON_ECT, 0);
                ASSERT_NE(nullptr, ServerSendContext);

                auto ServerDatagram =
                    CxPlatDataPathBindingAllocSendDatagram(ServerSendContext, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerDatagram);

                memcpy(ServerDatagram->Buffer, recvBuffer->Buffer, recvBuffer->BufferLength);

                VERIFY_CXPLAT_SUCCESS(
                    CxPlatDataPathBindingSend(
                        binding,
                        &recvBuffer->Tuple->LocalAddress,
                        &recvBuffer->Tuple->RemoteAddress,
                        ServerSendContext
                    ));

            } else {
                CxPlatEventSet(RecvContext->ClientCompletion);
            }

            recvBuffer = recvBuffer->Next;
        }

        CxPlatDataPathBindingReturnRecvDatagrams(recvBufferChain);
    }

    static void
    DataRecvCallbackECT0(
        _In_ CXPLAT_DATAPATH_BINDING* binding,
        _In_ void * recvContext,
        _In_ CXPLAT_RECV_DATAGRAM* recvBufferChain
        )
    {
        DataRecvContext* RecvContext = (DataRecvContext*)recvContext;
        ASSERT_NE(nullptr, RecvContext);

        CXPLAT_RECV_DATAGRAM* recvBuffer = recvBufferChain;

        while (recvBuffer != NULL) {
            ASSERT_EQ(recvBuffer->BufferLength, ExpectedDataSize);
            ASSERT_EQ(0, memcmp(recvBuffer->Buffer, ExpectedData, ExpectedDataSize));

            if (recvBuffer->Tuple->LocalAddress.Ipv4.sin_port == RecvContext->ServerAddress.Ipv4.sin_port) {

                CXPLAT_ECN_TYPE ecn = (CXPLAT_ECN_TYPE)recvBuffer->TypeOfService;

                auto ServerSendContext =
                    CxPlatDataPathBindingAllocSendContext(binding, CXPLAT_ECN_ECT_0, 0);
                ASSERT_NE(nullptr, ServerSendContext);

                auto ServerDatagram =
                    CxPlatDataPathBindingAllocSendDatagram(ServerSendContext, ExpectedDataSize);
                ASSERT_NE(nullptr, ServerDatagram);
                ASSERT_EQ(ecn, CXPLAT_ECN_ECT_0);

                memcpy(ServerDatagram->Buffer, recvBuffer->Buffer, recvBuffer->BufferLength);

                VERIFY_CXPLAT_SUCCESS(
                    CxPlatDataPathBindingSend(
                        binding,
                        &recvBuffer->Tuple->LocalAddress,
                        &recvBuffer->Tuple->RemoteAddress,
                        ServerSendContext
                    ));

            } else {
                CxPlatEventSet(RecvContext->ClientCompletion);
            }

            recvBuffer = recvBuffer->Next;
        }

        CxPlatDataPathBindingReturnRecvDatagrams(recvBufferChain);
    }
};

volatile uint16_t DataPathTest::NextPort;
CxPlatAddr DataPathTest::LocalIPv4;
CxPlatAddr DataPathTest::LocalIPv6;

TEST_F(DataPathTest, Initialize)
{
    CXPLAT_DATAPATH* datapath = nullptr;

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(datapath, nullptr);

    CxPlatDataPathUninitialize(
        datapath);
}

TEST_F(DataPathTest, InitializeInvalid)
{
    ASSERT_EQ(CXPLAT_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            nullptr));

    CXPLAT_DATAPATH* datapath = nullptr;
    ASSERT_EQ(CXPLAT_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            nullptr,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_EQ(CXPLAT_STATUS_INVALID_PARAMETER,
        CxPlatDataPathInitialize(
            0,
            EmptyReceiveCallback,
            nullptr,
            &datapath));
}

TEST_F(DataPathTest, Bind)
{
    CXPLAT_DATAPATH* datapath = nullptr;
    CXPLAT_DATAPATH_BINDING* binding = nullptr;

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(datapath, nullptr);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding));
    ASSERT_NE(nullptr, binding);

    CXPLAT_ADDR Address;
    CxPlatDataPathBindingGetLocalAddress(binding, &Address);
    ASSERT_NE(Address.Ipv4.sin_port, (uint16_t)0);

    CxPlatDataPathBindingDelete(binding);

    CxPlatDataPathUninitialize(
        datapath);
}

TEST_F(DataPathTest, Rebind)
{
    CXPLAT_DATAPATH* datapath = nullptr;
    CXPLAT_DATAPATH_BINDING* binding1 = nullptr;
    CXPLAT_DATAPATH_BINDING* binding2 = nullptr;

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            EmptyReceiveCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding1));
    ASSERT_NE(nullptr, binding1);

    CXPLAT_ADDR Address1;
    CxPlatDataPathBindingGetLocalAddress(binding1, &Address1);
    ASSERT_NE(Address1.Ipv4.sin_port, (uint16_t)0);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            nullptr,
            nullptr,
            &binding2));
    ASSERT_NE(nullptr, binding2);

    CXPLAT_ADDR Address2;
    CxPlatDataPathBindingGetLocalAddress(binding2, &Address2);
    ASSERT_NE(Address2.Ipv4.sin_port, (uint16_t)0);

    CxPlatDataPathBindingDelete(binding1);
    CxPlatDataPathBindingDelete(binding2);

    CxPlatDataPathUninitialize(
        datapath);
}

TEST_P(DataPathTest, Data)
{
    CXPLAT_DATAPATH* datapath = nullptr;
    CXPLAT_DATAPATH_BINDING* server = nullptr;
    CXPLAT_DATAPATH_BINDING* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    CxPlatEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            DataRecvCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    CXPLAT_STATUS Status = CXPLAT_STATUS_ADDRESS_IN_USE;
    while (Status == CXPLAT_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatDataPathBindingCreate(
                datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
                &server);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = CXPLAT_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_CXPLAT_SUCCESS(Status);
    ASSERT_NE(nullptr, server);
    CxPlatDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        CxPlatDataPathBindingAllocSendContext(client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        CxPlatDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    CXPLAT_ADDR ClientAddress;
    CxPlatDataPathBindingGetLocalAddress(client, &ClientAddress);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatDataPathBindingDelete(client);
    CxPlatDataPathBindingDelete(server);

    CxPlatDataPathUninitialize(
        datapath);

    CxPlatEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, DataRebind)
{
    CXPLAT_DATAPATH* datapath = nullptr;
    CXPLAT_DATAPATH_BINDING* server = nullptr;
    CXPLAT_DATAPATH_BINDING* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    CxPlatEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            DataRecvCallback,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    CXPLAT_STATUS Status = CXPLAT_STATUS_ADDRESS_IN_USE;
    while (Status == CXPLAT_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatDataPathBindingCreate(
                datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
                &server);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = CXPLAT_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_CXPLAT_SUCCESS(Status);
    ASSERT_NE(nullptr, server);
    CxPlatDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        CxPlatDataPathBindingAllocSendContext(client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        CxPlatDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    CXPLAT_ADDR ClientAddress;
    CxPlatDataPathBindingGetLocalAddress(client, &ClientAddress);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatDataPathBindingDelete(client);
    client = nullptr;
    CxPlatEventReset(RecvContext.ClientCompletion);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    ClientSendContext =
        CxPlatDataPathBindingAllocSendContext(client, CXPLAT_ECN_NON_ECT, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    ClientDatagram =
        CxPlatDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    CxPlatDataPathBindingGetLocalAddress(client, &ClientAddress);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatDataPathBindingDelete(client);
    CxPlatDataPathBindingDelete(server);

    CxPlatDataPathUninitialize(
        datapath);

    CxPlatEventUninitialize(RecvContext.ClientCompletion);
}

TEST_P(DataPathTest, DataECT0)
{
    CXPLAT_DATAPATH* datapath = nullptr;
    CXPLAT_DATAPATH_BINDING* server = nullptr;
    CXPLAT_DATAPATH_BINDING* client = nullptr;
    auto serverAddress = GetNewLocalAddr();

    DataRecvContext RecvContext = {};

    CxPlatEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathInitialize(
            0,
            DataRecvCallbackECT0,
            EmptyUnreachableCallback,
            &datapath));
    ASSERT_NE(nullptr, datapath);

    CXPLAT_STATUS Status = CXPLAT_STATUS_ADDRESS_IN_USE;
    while (Status == CXPLAT_STATUS_ADDRESS_IN_USE) {
        serverAddress.SockAddr.Ipv4.sin_port = GetNextPort();
        Status =
            CxPlatDataPathBindingCreate(
                datapath,
                &serverAddress.SockAddr,
                nullptr,
                &RecvContext,
                &server);
#ifdef _WIN32
        if (Status == HRESULT_FROM_WIN32(WSAEACCES)) {
            Status = CXPLAT_STATUS_ADDRESS_IN_USE;
            std::cout << "Replacing EACCESS with ADDRINUSE for port: " <<
                htons(serverAddress.SockAddr.Ipv4.sin_port) << std::endl;
        }
#endif //_WIN32
    }
    VERIFY_CXPLAT_SUCCESS(Status);
    ASSERT_NE(nullptr, server);
    CxPlatDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);
    ASSERT_NE(RecvContext.ServerAddress.Ipv4.sin_port, (uint16_t)0);
    serverAddress.SetPort(RecvContext.ServerAddress.Ipv4.sin_port);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingCreate(
            datapath,
            nullptr,
            &serverAddress.SockAddr,
            &RecvContext,
            &client));
    ASSERT_NE(nullptr, client);

    auto ClientSendContext =
        CxPlatDataPathBindingAllocSendContext(client, CXPLAT_ECN_ECT_0, 0);
    ASSERT_NE(nullptr, ClientSendContext);

    auto ClientDatagram =
        CxPlatDataPathBindingAllocSendDatagram(ClientSendContext, ExpectedDataSize);
    ASSERT_NE(nullptr, ClientDatagram);

    memcpy(ClientDatagram->Buffer, ExpectedData, ExpectedDataSize);

    CXPLAT_ADDR ClientAddress;
    CxPlatDataPathBindingGetLocalAddress(client, &ClientAddress);

    VERIFY_CXPLAT_SUCCESS(
        CxPlatDataPathBindingSend(
            client,
            &ClientAddress,
            &serverAddress.SockAddr,
            ClientSendContext));

    ASSERT_TRUE(CxPlatEventWaitWithTimeout(RecvContext.ClientCompletion, 2000));

    CxPlatDataPathBindingDelete(client);
    CxPlatDataPathBindingDelete(server);

    CxPlatDataPathUninitialize(
        datapath);

    CxPlatEventUninitialize(RecvContext.ClientCompletion);
}

INSTANTIATE_TEST_SUITE_P(DataPathTest, DataPathTest, ::testing::Values(4, 6), testing::PrintToStringParamName());
