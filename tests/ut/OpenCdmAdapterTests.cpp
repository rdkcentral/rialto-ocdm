/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 Sky UK
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "OpenCDMSessionMock.h"
#include "opencdm/open_cdm_adapter.h"
#include <gst/gst.h>
#include <gtest/gtest.h>

using testing::Return;
using testing::StrictMock;

namespace
{
constexpr uint32_t kSubSampleCount{12};
constexpr uint32_t kInitWithLast15{1};
} // namespace

class OpenCdmAdapterTests : public testing::Test
{
protected:
    StrictMock<OpenCDMSessionMock> m_openCdmSessionMock;
    GstBuffer m_buffer{};
    GstBuffer m_subSample{};
    GstBuffer m_iv{};
    GstBuffer m_keyId{};
    GstCaps m_caps{};
};

TEST_F(OpenCdmAdapterTests, ShouldFailToDecryptWhenSessionIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_gstreamer_session_decrypt(nullptr, &m_buffer, &m_subSample, kSubSampleCount, &m_iv,
                                                            &m_keyId, kInitWithLast15));
}

TEST_F(OpenCdmAdapterTests, ShouldDecrypt)
{
    EXPECT_CALL(m_openCdmSessionMock,
                addProtectionMeta(&m_buffer, &m_subSample, kSubSampleCount, &m_iv, &m_keyId, kInitWithLast15));
    EXPECT_EQ(ERROR_NONE, opencdm_gstreamer_session_decrypt(&m_openCdmSessionMock, &m_buffer, &m_subSample,
                                                            kSubSampleCount, &m_iv, &m_keyId, kInitWithLast15));
}

// function not declared in official interface (?)
OpenCDMError opencdm_gstreamer_transform_caps(GstCaps **caps);
TEST_F(OpenCdmAdapterTests, ShouldTransformCaps)
{
    EXPECT_EQ(ERROR_NONE, opencdm_gstreamer_transform_caps(nullptr));
}

TEST_F(OpenCdmAdapterTests, ShouldFailToDecryptBufferWhenSessionIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_gstreamer_session_decrypt_buffer(nullptr, &m_buffer, &m_caps));
}

TEST_F(OpenCdmAdapterTests, ShouldFailToDecryptBufferWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, addProtectionMeta(&m_buffer)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_gstreamer_session_decrypt_buffer(&m_openCdmSessionMock, &m_buffer, &m_caps));
}

TEST_F(OpenCdmAdapterTests, ShouldDecryptBuffer)
{
    EXPECT_CALL(m_openCdmSessionMock, addProtectionMeta(&m_buffer)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_gstreamer_session_decrypt_buffer(&m_openCdmSessionMock, &m_buffer, &m_caps));
}
