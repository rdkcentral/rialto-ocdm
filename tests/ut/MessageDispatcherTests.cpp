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

#include "MediaKeysClientMock.h"
#include "MessageDispatcher.h"
#include <gtest/gtest.h>

using testing::StrictMock;

namespace
{
constexpr int32_t kKeySessionId{12};
const std::vector<unsigned char> kMessage{'a', 'b', 'c'};
const std::string kUrl{"example.url"};
const std::vector<uint8_t> kKeyId{1, 2, 3, 4};
const firebolt::rialto::KeyStatusVector kKeyStatusVec{std::make_pair(kKeyId, firebolt::rialto::KeyStatus::USABLE)};
} // namespace

class MessageDispatcherTests : public testing::Test
{
protected:
    StrictMock<firebolt::rialto::MediaKeysClientMock> m_mediaKeysClientMock;
    MessageDispatcher m_sut{};
};

TEST_F(MessageDispatcherTests, shouldForwardLicenseRequest)
{
    auto client{m_sut.createClient(&m_mediaKeysClientMock)};
    EXPECT_CALL(m_mediaKeysClientMock, onLicenseRequest(kKeySessionId, kMessage, kUrl));
    m_sut.onLicenseRequest(kKeySessionId, kMessage, kUrl);
    client.reset();
}

TEST_F(MessageDispatcherTests, shouldForwardLicenseRenewal)
{
    auto client{m_sut.createClient(&m_mediaKeysClientMock)};
    EXPECT_CALL(m_mediaKeysClientMock, onLicenseRenewal(kKeySessionId, kMessage));
    m_sut.onLicenseRenewal(kKeySessionId, kMessage);
    client.reset();
}

TEST_F(MessageDispatcherTests, shouldForwardKeyStatusChange)
{
    auto client{m_sut.createClient(&m_mediaKeysClientMock)};
    EXPECT_CALL(m_mediaKeysClientMock, onKeyStatusesChanged(kKeySessionId, kKeyStatusVec));
    m_sut.onKeyStatusesChanged(kKeySessionId, kKeyStatusVec);
    client.reset();
}

TEST_F(MessageDispatcherTests, shouldNotForwardMessagesWhenNoClientIsCreated)
{
    m_sut.onLicenseRequest(kKeySessionId, kMessage, kUrl);
    m_sut.onLicenseRenewal(kKeySessionId, kMessage);
    m_sut.onKeyStatusesChanged(kKeySessionId, kKeyStatusVec);
}

TEST_F(MessageDispatcherTests, shouldNotForwardMessagesWhenClientIsRemoved)
{
    auto client{m_sut.createClient(&m_mediaKeysClientMock)};
    client.reset();
    m_sut.onLicenseRequest(kKeySessionId, kMessage, kUrl);
    m_sut.onLicenseRenewal(kKeySessionId, kMessage);
    m_sut.onKeyStatusesChanged(kKeySessionId, kKeyStatusVec);
}
