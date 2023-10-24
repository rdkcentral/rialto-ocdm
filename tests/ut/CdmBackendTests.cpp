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

#include "CdmBackend.h"
#include "MediaKeysClientMock.h"
#include "MediaKeysMock.h"
#include <gtest/gtest.h>

using firebolt::rialto::MediaKeysFactoryMock;
using testing::_;
using testing::ByMove;
using testing::Return;
using testing::StrictMock;

namespace
{
const std::string kKeySystem{"com.netflix.playready"};
const std::vector<uint8_t> kBytes{1, 2, 3, 4};
constexpr int32_t kKeySessionId{17};
constexpr firebolt::rialto::KeySessionType kSessionType{firebolt::rialto::KeySessionType::TEMPORARY};
constexpr bool kIsLDL{true};
constexpr firebolt::rialto::InitDataType kInitDataType{firebolt::rialto::InitDataType::DRMHEADER};
} // namespace

class CdmBackendTests : public testing::Test
{
public:
    CdmBackendTests() = default;
    ~CdmBackendTests() override = default;

    void changeStateToRunning()
    {
        ASSERT_TRUE(m_mediaKeysFactoryMock);

        EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem, _))
            .WillOnce(Return(ByMove(std::move(m_mediaKeysMock))));
        m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
    }

protected:
    std::shared_ptr<StrictMock<firebolt::rialto::MediaKeysClientMock>> m_mediaKeysClientMock{
        std::make_shared<StrictMock<firebolt::rialto::MediaKeysClientMock>>()};
    std::shared_ptr<StrictMock<MediaKeysFactoryMock>> m_mediaKeysFactoryMock{
        std::dynamic_pointer_cast<StrictMock<MediaKeysFactoryMock>>(firebolt::rialto::IMediaKeysFactory::createFactory())};
    std::unique_ptr<StrictMock<firebolt::rialto::MediaKeysMock>> m_mediaKeysMock{
        std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>()};
    CdmBackend m_sut{kKeySystem, m_mediaKeysClientMock, m_mediaKeysFactoryMock};
};

TEST_F(CdmBackendTests, ShouldChangeStateToInactive)
{
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::INACTIVE);
}

TEST_F(CdmBackendTests, ShouldChangeStateToRunning)
{
    changeStateToRunning();
}

TEST_F(CdmBackendTests, ShouldDoNothingWhenSwitchedToTheSameState)
{
    changeStateToRunning();
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
}

TEST_F(CdmBackendTests, ShouldInitializeMediaKeysWhenSwitchedToRunningAgain)
{
    changeStateToRunning();
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::INACTIVE);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem, _))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
}

TEST_F(CdmBackendTests, ShouldNotInitializeTwice)
{
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::INACTIVE);
    EXPECT_TRUE(m_sut.initialize(firebolt::rialto::ApplicationState::INACTIVE));
}

TEST_F(CdmBackendTests, ShouldInitializeWithoutMediaKeysCreationInInactiveState)
{
    EXPECT_TRUE(m_sut.initialize(firebolt::rialto::ApplicationState::INACTIVE));
}

TEST_F(CdmBackendTests, ShouldFailToInitializeInRunningStateWhenFactoryIsNull)
{
    CdmBackend invalidSut{kKeySystem, m_mediaKeysClientMock, nullptr};
    EXPECT_FALSE(invalidSut.initialize(firebolt::rialto::ApplicationState::RUNNING));
}

TEST_F(CdmBackendTests, ShouldFailToInitializeInRunningStateWhenMediaKeysIsNull)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem, _)).WillOnce(Return(nullptr));
    EXPECT_FALSE(m_sut.initialize(firebolt::rialto::ApplicationState::RUNNING));
}

TEST_F(CdmBackendTests, ShouldInitializeInRunningState)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem, _))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    EXPECT_TRUE(m_sut.initialize(firebolt::rialto::ApplicationState::RUNNING));
}

TEST_F(CdmBackendTests, ShouldFailToSelectKeyIdWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.selectKeyId(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToSelectKeyId)
{
    EXPECT_CALL(*m_mediaKeysMock, selectKeyId(kKeySessionId, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.selectKeyId(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldSelectKeyId)
{
    EXPECT_CALL(*m_mediaKeysMock, selectKeyId(kKeySessionId, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.selectKeyId(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldNotContainKeyWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.containsKey(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldNotContainKey)
{
    EXPECT_CALL(*m_mediaKeysMock, containsKey(kKeySessionId, kBytes)).WillOnce(Return(false));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.containsKey(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldContainKey)
{
    EXPECT_CALL(*m_mediaKeysMock, containsKey(kKeySessionId, kBytes)).WillOnce(Return(true));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.containsKey(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToCreateKeySessionWhenMediaKeysIsNotPresent)
{
    int32_t keySessionId{0};
    EXPECT_FALSE(m_sut.createKeySession(kSessionType, kIsLDL, keySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToCreateKeySession)
{
    int32_t keySessionId{0};
    EXPECT_CALL(*m_mediaKeysMock, createKeySession(kSessionType, _, kIsLDL, _))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.createKeySession(kSessionType, kIsLDL, keySessionId));
}

TEST_F(CdmBackendTests, ShouldCreateKeySession)
{
    int32_t keySessionId{0};
    EXPECT_CALL(*m_mediaKeysMock, createKeySession(kSessionType, _, kIsLDL, _))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.createKeySession(kSessionType, kIsLDL, keySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToGenerateRequestWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.generateRequest(kKeySessionId, kInitDataType, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToGenerateRequest)
{
    EXPECT_CALL(*m_mediaKeysMock, generateRequest(kKeySessionId, kInitDataType, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.generateRequest(kKeySessionId, kInitDataType, kBytes));
}

TEST_F(CdmBackendTests, ShouldGenerateRequest)
{
    EXPECT_CALL(*m_mediaKeysMock, generateRequest(kKeySessionId, kInitDataType, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.generateRequest(kKeySessionId, kInitDataType, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToLoadSessionWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.loadSession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToLoadSession)
{
    EXPECT_CALL(*m_mediaKeysMock, loadSession(kKeySessionId)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.loadSession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldLoadSession)
{
    EXPECT_CALL(*m_mediaKeysMock, loadSession(kKeySessionId)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.loadSession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToUpdateSessionWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.updateSession(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToUpdateSession)
{
    EXPECT_CALL(*m_mediaKeysMock, updateSession(kKeySessionId, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.updateSession(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldUpdateSession)
{
    EXPECT_CALL(*m_mediaKeysMock, updateSession(kKeySessionId, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.updateSession(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToSetDrmHeaderWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.setDrmHeader(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToSetDrmHeader)
{
    EXPECT_CALL(*m_mediaKeysMock, setDrmHeader(kKeySessionId, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.setDrmHeader(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldSetDrmHeader)
{
    EXPECT_CALL(*m_mediaKeysMock, setDrmHeader(kKeySessionId, kBytes))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.setDrmHeader(kKeySessionId, kBytes));
}

TEST_F(CdmBackendTests, ShouldFailToCloseKeySessionWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.closeKeySession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToCloseKeySession)
{
    EXPECT_CALL(*m_mediaKeysMock, closeKeySession(kKeySessionId))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.closeKeySession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldCloseKeySession)
{
    EXPECT_CALL(*m_mediaKeysMock, closeKeySession(kKeySessionId))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.closeKeySession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToRemoveKeySessionWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.removeKeySession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToRemoveKeySession)
{
    EXPECT_CALL(*m_mediaKeysMock, removeKeySession(kKeySessionId))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.removeKeySession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldRemoveKeySession)
{
    EXPECT_CALL(*m_mediaKeysMock, removeKeySession(kKeySessionId))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.removeKeySession(kKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToDeleteDrmStoreWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.deleteDrmStore());
}

TEST_F(CdmBackendTests, ShouldFailToDeleteDrmStore)
{
    EXPECT_CALL(*m_mediaKeysMock, deleteDrmStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.deleteDrmStore());
}

TEST_F(CdmBackendTests, ShouldDeleteDrmStore)
{
    EXPECT_CALL(*m_mediaKeysMock, deleteDrmStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.deleteDrmStore());
}

TEST_F(CdmBackendTests, ShouldFailToDeleteKeyStoreWhenMediaKeysIsNotPresent)
{
    EXPECT_FALSE(m_sut.deleteKeyStore());
}

TEST_F(CdmBackendTests, ShouldFailToDeleteKeyStore)
{
    EXPECT_CALL(*m_mediaKeysMock, deleteKeyStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.deleteKeyStore());
}

TEST_F(CdmBackendTests, ShouldDeleteKeyStore)
{
    EXPECT_CALL(*m_mediaKeysMock, deleteKeyStore()).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.deleteKeyStore());
}

TEST_F(CdmBackendTests, ShouldFailToGetDrmStoreHashWhenMediaKeysIsNotPresent)
{
    std::vector<unsigned char> drmStoreHash{};
    EXPECT_FALSE(m_sut.getDrmStoreHash(drmStoreHash));
}

TEST_F(CdmBackendTests, ShouldFailToGetDrmStoreHash)
{
    std::vector<unsigned char> drmStoreHash{};
    EXPECT_CALL(*m_mediaKeysMock, getDrmStoreHash(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.getDrmStoreHash(drmStoreHash));
}

TEST_F(CdmBackendTests, ShouldGetDrmStoreHash)
{
    std::vector<unsigned char> drmStoreHash{};
    EXPECT_CALL(*m_mediaKeysMock, getDrmStoreHash(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.getDrmStoreHash(drmStoreHash));
}

TEST_F(CdmBackendTests, ShouldFailToGetKeyStoreHashWhenMediaKeysIsNotPresent)
{
    std::vector<unsigned char> keyStoreHash{};
    EXPECT_FALSE(m_sut.getKeyStoreHash(keyStoreHash));
}

TEST_F(CdmBackendTests, ShouldFailToGetKeyStoreHash)
{
    std::vector<unsigned char> keyStoreHash{};
    EXPECT_CALL(*m_mediaKeysMock, getKeyStoreHash(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.getKeyStoreHash(keyStoreHash));
}

TEST_F(CdmBackendTests, ShouldGetKeyStoreHash)
{
    std::vector<unsigned char> keyStoreHash{};
    EXPECT_CALL(*m_mediaKeysMock, getKeyStoreHash(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.getKeyStoreHash(keyStoreHash));
}

TEST_F(CdmBackendTests, ShouldFailToGetLdlSessionsLimitWhenMediaKeysIsNotPresent)
{
    uint32_t ldlSessionsLimit{0};
    EXPECT_FALSE(m_sut.getLdlSessionsLimit(ldlSessionsLimit));
}

TEST_F(CdmBackendTests, ShouldFailToGetLdlSessionsLimit)
{
    uint32_t ldlSessionsLimit{0};
    EXPECT_CALL(*m_mediaKeysMock, getLdlSessionsLimit(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.getLdlSessionsLimit(ldlSessionsLimit));
}

TEST_F(CdmBackendTests, ShouldGetLdlSessionsLimit)
{
    uint32_t ldlSessionsLimit{0};
    EXPECT_CALL(*m_mediaKeysMock, getLdlSessionsLimit(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.getLdlSessionsLimit(ldlSessionsLimit));
}

TEST_F(CdmBackendTests, ShouldFailToGetLastDrmErrorWhenMediaKeysIsNotPresent)
{
    uint32_t lastDrmError{0};
    EXPECT_FALSE(m_sut.getLastDrmError(kKeySessionId, lastDrmError));
}

TEST_F(CdmBackendTests, ShouldFailToGetLastDrmError)
{
    uint32_t lastDrmError{0};
    EXPECT_CALL(*m_mediaKeysMock, getLastDrmError(kKeySessionId, _))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.getLastDrmError(kKeySessionId, lastDrmError));
}

TEST_F(CdmBackendTests, ShouldGetLastDrmError)
{
    uint32_t lastDrmError{0};
    EXPECT_CALL(*m_mediaKeysMock, getLastDrmError(kKeySessionId, _))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.getLastDrmError(kKeySessionId, lastDrmError));
}

TEST_F(CdmBackendTests, ShouldFailToGetDrmTimeWhenMediaKeysIsNotPresent)
{
    uint64_t drmTime{0};
    EXPECT_FALSE(m_sut.getDrmTime(drmTime));
}

TEST_F(CdmBackendTests, ShouldFailToGetDrmTime)
{
    uint64_t drmTime{0};
    EXPECT_CALL(*m_mediaKeysMock, getDrmTime(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.getDrmTime(drmTime));
}

TEST_F(CdmBackendTests, ShouldGetDrmTime)
{
    uint64_t drmTime{0};
    EXPECT_CALL(*m_mediaKeysMock, getDrmTime(_)).WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.getDrmTime(drmTime));
}

TEST_F(CdmBackendTests, ShouldFailToGetCdmKeySessionIdWhenMediaKeysIsNotPresent)
{
    std::string cdmKeySessionId{};
    EXPECT_FALSE(m_sut.getCdmKeySessionId(kKeySessionId, cdmKeySessionId));
}

TEST_F(CdmBackendTests, ShouldFailToGetCdmKeySessionId)
{
    std::string cdmKeySessionId{};
    EXPECT_CALL(*m_mediaKeysMock, getCdmKeySessionId(kKeySessionId, _))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::FAIL));
    changeStateToRunning();
    EXPECT_FALSE(m_sut.getCdmKeySessionId(kKeySessionId, cdmKeySessionId));
}

TEST_F(CdmBackendTests, ShouldGetCdmKeySessionId)
{
    std::string cdmKeySessionId{};
    EXPECT_CALL(*m_mediaKeysMock, getCdmKeySessionId(kKeySessionId, _))
        .WillOnce(Return(firebolt::rialto::MediaKeyErrorStatus::OK));
    changeStateToRunning();
    EXPECT_TRUE(m_sut.getCdmKeySessionId(kKeySessionId, cdmKeySessionId));
}
