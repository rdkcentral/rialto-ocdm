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

#include "CdmBackendMock.h"
#include "MessageDispatcherMock.h"
#include "OcdmSessionsCallbacksMock.h"
#include "OpenCDMSessionPrivate.h"
#include <MessageDispatcherClientMock.h>
#include <gtest/gtest.h>

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Return;
using testing::SetArgReferee;
using testing::StrictMock;

namespace
{
constexpr LicenseType kSessionType{LicenseType::Temporary};
constexpr firebolt::rialto::KeySessionType kRialtoSessionType{firebolt::rialto::KeySessionType::TEMPORARY};
const std::string kInitDataType{"drmheader"};
constexpr firebolt::rialto::InitDataType kRialtoInitDataType{firebolt::rialto::InitDataType::DRMHEADER};
const std::vector<uint8_t> kInitData{4, 3, 2, 1};
const std::vector<uint8_t> kCdmData{1, 2, 3, 4};
constexpr bool kIsLdl{false};
constexpr int32_t kKeySessionId{14};
} // namespace

class OpenCdmSessionTests : public testing::Test
{
protected:
    std::shared_ptr<StrictMock<CdmBackendMock>> m_cdmBackendMock{std::make_shared<StrictMock<CdmBackendMock>>()};
    std::shared_ptr<StrictMock<MessageDispatcherMock>> m_messageDispatcherMock{
        std::make_shared<StrictMock<MessageDispatcherMock>>()};
    OpenCDMSessionCallbacks m_callbacks{processChallengeCallback, keyUpdateCallback, errorMessageCallback,
                                        keysUpdatedCallback};
    int m_userData{12};
    std::unique_ptr<OpenCDMSessionPrivate> m_sut;

    void createSut(const LicenseType &licenseType = kSessionType)
    {
        m_sut = std::make_unique<OpenCDMSessionPrivate>(m_cdmBackendMock, m_messageDispatcherMock, licenseType,
                                                        &m_callbacks, &m_userData, kInitDataType, kInitData);
    }

    void createInvalidSut()
    {
        m_sut = std::make_unique<OpenCDMSessionPrivate>(nullptr, nullptr, kSessionType, &m_callbacks, &m_userData,
                                                        kInitDataType, kInitData);
    }

    void initializeSut(const firebolt::rialto::KeySessionType &sessionType = kRialtoSessionType)
    {
        EXPECT_CALL(*m_cdmBackendMock, createKeySession(sessionType, kIsLdl, _))
            .WillOnce(DoAll(SetArgReferee<2>(kKeySessionId), Return(true)));
        EXPECT_CALL(*m_messageDispatcherMock, createClient(_))
            .WillOnce(Return(ByMove(std::make_unique<StrictMock<MessageDispatcherClientMock>>())));
        EXPECT_TRUE(m_sut->initialize());
    }
};

TEST_F(OpenCdmSessionTests, ShouldNotInitializeWhenBackendOrDispatcherIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->initialize());
}

TEST_F(OpenCdmSessionTests, ShouldNotInitializeWhenCreateKeySessionFails)
{
    createSut();
    EXPECT_CALL(*m_cdmBackendMock, createKeySession(kRialtoSessionType, kIsLdl, _)).WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(_, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->initialize());
}

TEST_F(OpenCdmSessionTests, ShouldInitialize)
{
    createSut();
    initializeSut();
}

TEST_F(OpenCdmSessionTests, ShouldInitializeWithAllPossibleLicenseTypes)
{
    createSut(LicenseType::PersistentUsageRecord);
    initializeSut(firebolt::rialto::KeySessionType::UNKNOWN);

    createSut(LicenseType::PersistentLicense);
    initializeSut(firebolt::rialto::KeySessionType::PERSISTENT_LICENCE);

    createSut(static_cast<LicenseType>(7)); // some uknown license type
    initializeSut(firebolt::rialto::KeySessionType::UNKNOWN);
}

TEST_F(OpenCdmSessionTests, ShouldNotInitializeTwice)
{
    createSut();
    initializeSut();
    EXPECT_TRUE(m_sut->initialize());
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->generateRequest(kInitDataType, kInitData, kCdmData));
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenInitDataTypeIsUnknown)
{
    createSut();
    EXPECT_FALSE(m_sut->generateRequest("surprise", kInitData, kCdmData));
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->generateRequest(kInitDataType, kInitData, kCdmData));
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kInitData)).WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->generateRequest(kInitDataType, kInitData, kCdmData));
}

TEST_F(OpenCdmSessionTests, ShouldGenerateRequest)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kInitData)).WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest(kInitDataType, kInitData, kCdmData));
}

TEST_F(OpenCdmSessionTests, ShouldGenerateRequestForAllInitDataTypes)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, firebolt::rialto::InitDataType::CENC, kInitData))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest("cenc", kInitData, kCdmData));

    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, firebolt::rialto::InitDataType::WEBM, kInitData))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest("webm", kInitData, kCdmData));
}

TEST_F(OpenCdmSessionTests, ShouldNotLoadSessionWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->loadSession());
}

TEST_F(OpenCdmSessionTests, ShouldNotLoadSessionWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->loadSession());
}

TEST_F(OpenCdmSessionTests, ShouldFailToLoadSessionWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, loadSession(kKeySessionId)).WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->loadSession());
}

TEST_F(OpenCdmSessionTests, ShouldLoadSession)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, loadSession(kKeySessionId)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->loadSession());
}
