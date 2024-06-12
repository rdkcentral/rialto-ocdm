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
#include "ControlMock.h"
#include "MediaKeysMock.h"
#include "OcdmSessionsCallbacksMock.h"
#include "OpenCDMSystemPrivate.h"
#include <gtest/gtest.h>

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Return;
using testing::SetArgReferee;
using testing::StrictMock;

namespace
{
const std::string kKeySystem{"com.netflix.playready"};
const std::string kMetadata{"metadata"};
constexpr firebolt::rialto::ApplicationState kAppState{firebolt::rialto::ApplicationState::RUNNING};
constexpr LicenseType kLicenseType{LicenseType::Temporary};
const std::string kInitDataType{"drmheader"};
const std::vector<uint8_t> kBytes{1, 2, 3, 4};
} // namespace

class OpenCdmSystemTests : public testing::Test
{
protected:
    std::shared_ptr<StrictMock<firebolt::rialto::ControlFactoryMock>> m_controlFactoryMock{
        std::dynamic_pointer_cast<StrictMock<firebolt::rialto::ControlFactoryMock>>(
            firebolt::rialto::IControlFactory::createFactory())};
    std::shared_ptr<StrictMock<firebolt::rialto::ControlMock>> m_controlMock{
        std::make_shared<StrictMock<firebolt::rialto::ControlMock>>()};
    std::shared_ptr<StrictMock<firebolt::rialto::MediaKeysFactoryMock>> m_mediaKeysFactoryMock{
        std::dynamic_pointer_cast<StrictMock<firebolt::rialto::MediaKeysFactoryMock>>(
            firebolt::rialto::IMediaKeysFactory::createFactory())};
    std::unique_ptr<StrictMock<firebolt::rialto::MediaKeysMock>> m_mediaKeys{
        std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>()};
    StrictMock<firebolt::rialto::MediaKeysMock> &m_mediaKeysMock{*m_mediaKeys};
    OpenCDMSessionCallbacks m_callbacks{processChallengeCallback, keyUpdateCallback, errorMessageCallback,
                                        keysUpdatedCallback};
    int m_userData{12};
    std::unique_ptr<OpenCDMSystemPrivate> m_sut;

    void createValidSut()
    {
        EXPECT_CALL(*m_controlFactoryMock, createControl()).WillOnce(Return(m_controlMock));
        EXPECT_CALL(*m_controlMock, registerClientAndUnregisterOnDestruction(_, _))
            .WillOnce(DoAll(SetArgReferee<1>(kAppState), Return(true)));
        EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem)).WillOnce(Return(ByMove(std::move(m_mediaKeys))));

        auto messageDispatcher = std::make_shared<MessageDispatcher>();
        auto cdmBackend = std::make_shared<CdmBackend>(kKeySystem, messageDispatcher,
                                                       firebolt::rialto::IMediaKeysFactory::createFactory());
        m_sut = std::make_unique<OpenCDMSystemPrivate>(kKeySystem.data(), kMetadata, messageDispatcher, cdmBackend);
    }

    void createInvalidSut()
    {
        EXPECT_CALL(*m_controlFactoryMock, createControl()).WillOnce(Return(m_controlMock));
        m_sut = std::make_unique<OpenCDMSystemPrivate>(kKeySystem.data(), kMetadata, nullptr, nullptr);
    }
};

TEST_F(OpenCdmSystemTests, ShouldReturnKeySystem)
{
    createValidSut();
    EXPECT_EQ(m_sut->keySystem(), kKeySystem);
}

TEST_F(OpenCdmSystemTests, ShouldReturnMetadata)
{
    createValidSut();
    EXPECT_EQ(m_sut->metadata(), kMetadata);
}

TEST_F(OpenCdmSystemTests, ShouldCreateSession)
{
    createValidSut();
    OpenCDMSession *session{m_sut->createSession(kLicenseType, &m_callbacks, &m_userData, kInitDataType, kBytes)};
    ASSERT_NE(nullptr, session);
    ActiveSessions::instance().remove(session);
}

TEST_F(OpenCdmSystemTests, ShouldNotGetDrmTimeWhenCdmServiceIsNull)
{
    uint64_t time{0};
    createInvalidSut();
    EXPECT_FALSE(m_sut->getDrmTime(time));
}

TEST_F(OpenCdmSystemTests, ShouldNotGetDrmTimeWhenOperationFails)
{
    uint64_t time{0};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getDrmTime(time)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    EXPECT_FALSE(m_sut->getDrmTime(time));
}

TEST_F(OpenCdmSystemTests, ShouldGetDrmTime)
{
    constexpr uint64_t kTime{1234};
    uint64_t time{0};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getDrmTime(time))
        .WillOnce(DoAll(SetArgReferee<0>(kTime), Return(firebolt::rialto::MediaKeyErrorStatus::OK)));
    EXPECT_TRUE(m_sut->getDrmTime(time));
    EXPECT_EQ(kTime, time);
}

TEST_F(OpenCdmSystemTests, ShouldNotGetLdlSessionsLimitWhenCdmServiceIsNull)
{
    uint32_t limit{0};
    createInvalidSut();
    EXPECT_FALSE(m_sut->getLdlSessionsLimit(limit));
}

TEST_F(OpenCdmSystemTests, ShouldNotGetLdlSessionsLimitWhenOperationFails)
{
    uint32_t limit{0};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getLdlSessionsLimit(limit)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    EXPECT_FALSE(m_sut->getLdlSessionsLimit(limit));
}

TEST_F(OpenCdmSystemTests, ShouldGetLdlSessionsLimit)
{
    constexpr uint32_t kLimit{1234};
    uint32_t limit{0};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getLdlSessionsLimit(limit))
        .WillOnce(DoAll(SetArgReferee<0>(kLimit), Return(firebolt::rialto::MediaKeyErrorStatus::OK)));
    EXPECT_TRUE(m_sut->getLdlSessionsLimit(limit));
    EXPECT_EQ(kLimit, limit);
}

TEST_F(OpenCdmSystemTests, ShouldNotGetKeyStoreHashWhenCdmServiceIsNull)
{
    std::vector<unsigned char> hash{};
    createInvalidSut();
    EXPECT_FALSE(m_sut->getKeyStoreHash(hash));
}

TEST_F(OpenCdmSystemTests, ShouldNotGetKeyStoreHashWhenOperationFails)
{
    std::vector<unsigned char> hash{};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getKeyStoreHash(hash)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    EXPECT_FALSE(m_sut->getKeyStoreHash(hash));
}

TEST_F(OpenCdmSystemTests, ShouldGetKeyStoreHash)
{
    const std::vector<unsigned char> kHash{'a', 'b', 'c'};
    std::vector<unsigned char> hash{};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getKeyStoreHash(hash))
        .WillOnce(DoAll(SetArgReferee<0>(kHash), Return(firebolt::rialto::MediaKeyErrorStatus::OK)));
    EXPECT_TRUE(m_sut->getKeyStoreHash(hash));
    EXPECT_EQ(kHash, hash);
}

TEST_F(OpenCdmSystemTests, ShouldNotGetDrmStoreHashWhenCdmServiceIsNull)
{
    std::vector<unsigned char> hash{};
    createInvalidSut();
    EXPECT_FALSE(m_sut->getDrmStoreHash(hash));
}

TEST_F(OpenCdmSystemTests, ShouldNotGetDrmStoreHashWhenOperationFails)
{
    std::vector<unsigned char> hash{};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getDrmStoreHash(hash)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    EXPECT_FALSE(m_sut->getDrmStoreHash(hash));
}

TEST_F(OpenCdmSystemTests, ShouldGetDrmStoreHash)
{
    const std::vector<unsigned char> kHash{'a', 'b', 'c'};
    std::vector<unsigned char> hash{};
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, getDrmStoreHash(hash))
        .WillOnce(DoAll(SetArgReferee<0>(kHash), Return(firebolt::rialto::MediaKeyErrorStatus::OK)));
    EXPECT_TRUE(m_sut->getDrmStoreHash(hash));
    EXPECT_EQ(kHash, hash);
}

TEST_F(OpenCdmSystemTests, ShouldNotDeleteKeyStoreWhenCdmServiceIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->deleteKeyStore());
}

TEST_F(OpenCdmSystemTests, ShouldNotDeleteKeyStoreWhenOperationFails)
{
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, deleteKeyStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    EXPECT_FALSE(m_sut->deleteKeyStore());
}

TEST_F(OpenCdmSystemTests, ShouldDeleteKeyStore)
{
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, deleteKeyStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    EXPECT_TRUE(m_sut->deleteKeyStore());
}

TEST_F(OpenCdmSystemTests, ShouldNotDeleteDrmStoreWhenCdmServiceIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->deleteDrmStore());
}

TEST_F(OpenCdmSystemTests, ShouldNotDeleteDrmStoreWhenOperationFails)
{
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, deleteDrmStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    EXPECT_FALSE(m_sut->deleteDrmStore());
}

TEST_F(OpenCdmSystemTests, ShouldDeleteDrmStore)
{
    createValidSut();
    EXPECT_CALL(m_mediaKeysMock, deleteDrmStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    EXPECT_TRUE(m_sut->deleteDrmStore());
}
