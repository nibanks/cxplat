/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#ifdef CXPLAT_CLOG
#include "main.cpp.clog.h"
#endif

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void CxPlatTraceRundown(void) { }

class CxPlatCoreTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        CxPlatPlatformSystemLoad();
        ASSERT_TRUE(CXPLAT_SUCCEEDED(CxPlatPlatformInitialize()));
    }
    void TearDown() override {
        CxPlatPlatformUninitialize();
        CxPlatPlatformSystemUnload();
    }
};

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new CxPlatCoreTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
