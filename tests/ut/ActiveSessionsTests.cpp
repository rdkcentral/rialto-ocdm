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

#include "ActiveSessions.h"
#include "CdmBackendMock.h"
#include "MessageDispatcherMock.h"
#include "OpenCDMSessionPrivate.h"
#include <MediaCommon.h>
#include <gtest/gtest.h>

using testing::StrictMock;

namespace
{
constexpr LicenseType kSessionType{LicenseType::Temporary};
constexpr void *kContext{nullptr};
const std::string kInitDataType{"drmheader"};
const std::vector<uint8_t> kInitData{4, 3, 2, 1};
const std::vector<uint8_t> kKeyId{1, 2, 3, 4};
const firebolt::rialto::KeyStatusVector kKeyStatusVec{std::make_pair(kKeyId, firebolt::rialto::KeyStatus::USABLE)};

void keyUpdateCb(struct OpenCDMSession *, void *, const uint8_t[], const uint8_t) {}
} // namespace

class ActiveSessionsTests : public testing::Test
{
public:
    ActiveSessionsTests() = default;
    ~ActiveSessionsTests() override = default;

protected:
    std::shared_ptr<StrictMock<CdmBackendMock>> m_cdmBackendMock{std::make_shared<StrictMock<CdmBackendMock>>()};
    std::shared_ptr<StrictMock<MessageDispatcherMock>> m_messageDispatcherMock{
        std::make_shared<StrictMock<MessageDispatcherMock>>()};
    OpenCDMSessionCallbacks m_callbacks{nullptr, keyUpdateCb, nullptr, nullptr};
};

TEST_F(ActiveSessionsTests, GetShouldReturnNullWhenSessionIsNotPresent)
{
    EXPECT_EQ(nullptr, ActiveSessions::instance().get(kKeyId));
}

TEST_F(ActiveSessionsTests, ShouldCreateSessionGetShouldFailForUknownKey)
{
    OpenCDMSession *session = ActiveSessions::instance().create(m_cdmBackendMock, m_messageDispatcherMock, kSessionType,
                                                                &m_callbacks, kContext, kInitDataType, kInitData);
    EXPECT_EQ(nullptr, ActiveSessions::instance().get(kKeyId));
    ActiveSessions::instance().remove(session);
}

TEST_F(ActiveSessionsTests, ShouldCreateSessionGetShouldSucceed)
{
    OpenCDMSession *session = ActiveSessions::instance().create(m_cdmBackendMock, m_messageDispatcherMock, kSessionType,
                                                                &m_callbacks, kContext, kInitDataType, kInitData);
    OpenCDMSessionPrivate *sessionPriv = dynamic_cast<OpenCDMSessionPrivate *>(session);
    ASSERT_NE(nullptr, sessionPriv);
    sessionPriv->onKeyStatusesChanged(firebolt::rialto::kInvalidSessionId, kKeyStatusVec);
    auto *gotSession = ActiveSessions::instance().get(kKeyId);
    EXPECT_EQ(session, gotSession);
    ActiveSessions::instance().remove(gotSession);
    ActiveSessions::instance().remove(session);
}

TEST_F(ActiveSessionsTests, SessionShouldExistUntilLastInstanceIsRemoved)
{
    OpenCDMSession *session = ActiveSessions::instance().create(m_cdmBackendMock, m_messageDispatcherMock, kSessionType,
                                                                &m_callbacks, kContext, kInitDataType, kInitData);
    OpenCDMSessionPrivate *sessionPriv = dynamic_cast<OpenCDMSessionPrivate *>(session);
    ASSERT_NE(nullptr, sessionPriv);
    sessionPriv->onKeyStatusesChanged(firebolt::rialto::kInvalidSessionId, kKeyStatusVec);
    auto *gotSession = ActiveSessions::instance().get(kKeyId);
    EXPECT_EQ(session, gotSession);
    ActiveSessions::instance().remove(session);
    auto *gotSession2 = ActiveSessions::instance().get(kKeyId);
    EXPECT_EQ(gotSession, gotSession2);
    ActiveSessions::instance().remove(gotSession);
    ActiveSessions::instance().remove(gotSession2);
    EXPECT_EQ(nullptr, ActiveSessions::instance().get(kKeyId));
}
