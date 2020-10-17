/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"

#define CXPLAT_TEST_APIS 1

#include "quic_platform.h"

#include "quic_trace.h"

#define VERIFY_CXPLAT_SUCCESS(result) ASSERT_TRUE(CXPLAT_SUCCEEDED(result))

#define GTEST_SKIP_NO_RETURN_(message) \
  GTEST_MESSAGE_(message, ::testing::TestPartResult::kSkip)
