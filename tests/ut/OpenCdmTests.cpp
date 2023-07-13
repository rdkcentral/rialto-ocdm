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

#include "ControlMock.h"
#include "MediaKeysCapabilitiesMock.h"
#include "OcdmSessionsCallbacksMock.h"
#include "OpenCDMSessionMock.h"
#include "OpenCDMSystemMock.h"
#include "opencdm/open_cdm.h"
#include <gtest/gtest.h>

using firebolt::rialto::ControlFactoryMock;
using firebolt::rialto::ControlMock;
using firebolt::rialto::MediaKeysCapabilitiesFactoryMock;
using firebolt::rialto::MediaKeysCapabilitiesMock;
using testing::_;
using testing::DoAll;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgReferee;
using testing::StrictMock;

namespace
{
const std::string kNetflixKeySystem{"com.netflix.playready"};
const std::string kWidevineKeySystem{"com.widevine.alpha"};
constexpr LicenseType kLicenseType{LicenseType::Temporary};
const std::string kInitDataType{"drmheader"};
const std::vector<uint8_t> kInitData{1, 2, 3, 4};
const std::vector<uint8_t> kCdmData{5, 6, 7, 8};
const std::string kSessionId{"abc"};
} // namespace

class OpenCdmTests : public testing::Test
{
protected:
    std::shared_ptr<StrictMock<ControlFactoryMock>> m_controlFactoryMock{
        std::dynamic_pointer_cast<StrictMock<ControlFactoryMock>>(firebolt::rialto::IControlFactory::createFactory())};
    std::shared_ptr<StrictMock<ControlMock>> m_controlMock{std::make_shared<StrictMock<ControlMock>>()};
    std::shared_ptr<StrictMock<MediaKeysCapabilitiesFactoryMock>> m_mediaKeysCapabilitiesFactoryMock{
        std::dynamic_pointer_cast<StrictMock<MediaKeysCapabilitiesFactoryMock>>(
            firebolt::rialto::IMediaKeysCapabilitiesFactory::createFactory())};
    std::shared_ptr<StrictMock<MediaKeysCapabilitiesMock>> m_mediaKeysCapabilitiesMock{
        std::dynamic_pointer_cast<StrictMock<MediaKeysCapabilitiesMock>>(
            m_mediaKeysCapabilitiesFactoryMock->getMediaKeysCapabilities())};
    StrictMock<OpenCDMSystemMock> m_openCdmSystemMock;
    StrictMock<OpenCDMSessionMock> m_openCdmSessionMock;
    OpenCDMSessionCallbacks m_callbacks{processChallengeCallback, keyUpdateCallback, errorMessageCallback,
                                        keysUpdatedCallback};
    int m_userData{18};
};

TEST_F(OpenCdmTests, ShouldCreateAndDestroySystem)
{
    EXPECT_CALL(*m_controlFactoryMock, createControl()).WillOnce(Return(m_controlMock));
    EXPECT_CALL(*m_controlMock, registerClient(_, _)).WillOnce(Return(true));
    auto *system{opencdm_create_system(kNetflixKeySystem.c_str())};
    EXPECT_NE(nullptr, system);
    EXPECT_EQ(ERROR_NONE, opencdm_destruct_system(system));
}

TEST_F(OpenCdmTests, ShouldCheckIfKeySystemIsSupported)
{
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, supportsKeySystem(kNetflixKeySystem)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_is_type_supported(kNetflixKeySystem.c_str(), nullptr));
}

TEST_F(OpenCdmTests, ShouldFailToGetMetadataWhenOneOfParamsIsNull)
{
    uint16_t metadataSize{100};
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_metadata(nullptr, nullptr, &metadataSize));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_metadata(&m_openCdmSystemMock, nullptr, nullptr));
}

TEST_F(OpenCdmTests, ShouldGetMetadata)
{
    uint16_t metadataSize{100};
    EXPECT_EQ(ERROR_NONE, opencdm_system_get_metadata(&m_openCdmSystemMock, nullptr, &metadataSize));
    EXPECT_EQ(0, metadataSize);
}

TEST_F(OpenCdmTests, ShouldFailToGetVersionWhenParamsAreNull)
{
    char versionStr[64];
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_version(nullptr, versionStr));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_version(&m_openCdmSystemMock, nullptr));
}

TEST_F(OpenCdmTests, ShouldFailToGetVersion)
{
    char versionStr[64];
    EXPECT_CALL(m_openCdmSystemMock, keySystem()).WillOnce(ReturnRef(kNetflixKeySystem));
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, getSupportedKeySystemVersion(kNetflixKeySystem, _)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_version(&m_openCdmSystemMock, versionStr));
}

TEST_F(OpenCdmTests, ShouldGetVersion)
{
    const std::string kVersion{"1.23"};
    char versionStr[64];
    EXPECT_CALL(m_openCdmSystemMock, keySystem()).WillOnce(ReturnRef(kNetflixKeySystem));
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, getSupportedKeySystemVersion(kNetflixKeySystem, _))
        .WillOnce(DoAll(SetArgReferee<1>(kVersion), Return(true)));
    EXPECT_EQ(ERROR_NONE, opencdm_system_get_version(&m_openCdmSystemMock, versionStr));
    EXPECT_EQ(kVersion, std::string(versionStr));
}

TEST_F(OpenCdmTests, ShouldFailToGetDrmTimeWhenOneOfArgsIsNull)
{
    uint64_t time;
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_drm_time(&m_openCdmSystemMock, nullptr));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_drm_time(nullptr, &time));
}

TEST_F(OpenCdmTests, ShouldFailToGetDrmTimeWhenOperationFails)
{
    uint64_t time;
    EXPECT_CALL(m_openCdmSystemMock, getDrmTime(_)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_get_drm_time(&m_openCdmSystemMock, &time));
}

TEST_F(OpenCdmTests, ShouldGetDrmTime)
{
    uint64_t kTime{124};
    uint64_t time;
    EXPECT_CALL(m_openCdmSystemMock, getDrmTime(_)).WillOnce(DoAll(SetArgReferee<0>(kTime), Return(true)));
    EXPECT_EQ(ERROR_NONE, opencdm_system_get_drm_time(&m_openCdmSystemMock, &time));
    EXPECT_EQ(kTime, time);
}

TEST_F(OpenCdmTests, ShouldGetSystemSession)
{
    // ActiveSessions tested in its own tests
    EXPECT_EQ(nullptr, opencdm_get_system_session(&m_openCdmSystemMock, nullptr, 0, 0));
}

TEST_F(OpenCdmTests, ShouldSetServerCertificate)
{
    EXPECT_EQ(ERROR_NONE, opencdm_system_set_server_certificate(&m_openCdmSystemMock, nullptr, 0));
}

TEST_F(OpenCdmTests, ShouldGetSession)
{
    // ActiveSessions tested in its own tests
    EXPECT_EQ(nullptr, opencdm_get_session(nullptr, 0, 0));
}

TEST_F(OpenCdmTests, ShouldFailToConstructSessionWhenSystemIsNull)
{
    OpenCDMSession *resultSession{nullptr};
    EXPECT_EQ(ERROR_FAIL, opencdm_construct_session(nullptr, kLicenseType, kInitDataType.c_str(), kInitData.data(),
                                                    kInitData.size(), kCdmData.data(), kCdmData.size(), &m_callbacks,
                                                    &m_userData, &resultSession));
    EXPECT_EQ(nullptr, resultSession);
}

TEST_F(OpenCdmTests, ShouldFailToConstructSessionWhenSessionIsInvalid)
{
    OpenCDMSession *resultSession{nullptr};
    EXPECT_CALL(m_openCdmSystemMock, createSession(kLicenseType, &m_callbacks, &m_userData, kInitDataType, kInitData))
        .WillOnce(Return(nullptr));
    EXPECT_EQ(ERROR_INVALID_SESSION,
              opencdm_construct_session(&m_openCdmSystemMock, kLicenseType, kInitDataType.c_str(), kInitData.data(),
                                        kInitData.size(), kCdmData.data(), kCdmData.size(), &m_callbacks, &m_userData,
                                        &resultSession));
    EXPECT_EQ(nullptr, resultSession);
}

TEST_F(OpenCdmTests, ShouldConstructPlayreadySession)
{
    OpenCDMSession *resultSession{nullptr};
    EXPECT_CALL(m_openCdmSystemMock, createSession(kLicenseType, &m_callbacks, &m_userData, kInitDataType, kInitData))
        .WillOnce(Return(&m_openCdmSessionMock));
    EXPECT_CALL(m_openCdmSystemMock, keySystem()).WillOnce(ReturnRef(kNetflixKeySystem));
    EXPECT_EQ(ERROR_NONE, opencdm_construct_session(&m_openCdmSystemMock, kLicenseType, kInitDataType.c_str(),
                                                    kInitData.data(), kInitData.size(), kCdmData.data(),
                                                    kCdmData.size(), &m_callbacks, &m_userData, &resultSession));
    EXPECT_EQ(&m_openCdmSessionMock, resultSession);
}

TEST_F(OpenCdmTests, ShouldFailToConstructWidevineSessionWhenInitializationFails)
{
    OpenCDMSession *resultSession{nullptr};
    EXPECT_CALL(m_openCdmSystemMock, createSession(kLicenseType, &m_callbacks, &m_userData, kInitDataType, kInitData))
        .WillOnce(Return(&m_openCdmSessionMock));
    EXPECT_CALL(m_openCdmSystemMock, keySystem()).WillOnce(ReturnRef(kWidevineKeySystem));
    EXPECT_CALL(m_openCdmSessionMock, initialize()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_construct_session(&m_openCdmSystemMock, kLicenseType, kInitDataType.c_str(),
                                                    kInitData.data(), kInitData.size(), kCdmData.data(),
                                                    kCdmData.size(), &m_callbacks, &m_userData, &resultSession));
    EXPECT_EQ(nullptr, resultSession);
}

TEST_F(OpenCdmTests, ShouldFailToConstructWidevineSessionWhenGenerateRequestFails)
{
    OpenCDMSession *resultSession{nullptr};
    EXPECT_CALL(m_openCdmSystemMock, createSession(kLicenseType, &m_callbacks, &m_userData, kInitDataType, kInitData))
        .WillOnce(Return(&m_openCdmSessionMock));
    EXPECT_CALL(m_openCdmSystemMock, keySystem()).WillOnce(ReturnRef(kWidevineKeySystem));
    EXPECT_CALL(m_openCdmSessionMock, initialize()).WillOnce(Return(true));
    EXPECT_CALL(m_openCdmSessionMock, generateRequest(kInitDataType, kInitData, kCdmData)).WillOnce(Return(false));
    EXPECT_CALL(m_openCdmSessionMock, closeSession()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_FAIL, opencdm_construct_session(&m_openCdmSystemMock, kLicenseType, kInitDataType.c_str(),
                                                    kInitData.data(), kInitData.size(), kCdmData.data(),
                                                    kCdmData.size(), &m_callbacks, &m_userData, &resultSession));
    EXPECT_EQ(nullptr, resultSession);
}

TEST_F(OpenCdmTests, ShouldConstructWidevineSession)
{
    OpenCDMSession *resultSession{nullptr};
    EXPECT_CALL(m_openCdmSystemMock, createSession(kLicenseType, &m_callbacks, &m_userData, kInitDataType, kInitData))
        .WillOnce(Return(&m_openCdmSessionMock));
    EXPECT_CALL(m_openCdmSystemMock, keySystem()).WillOnce(ReturnRef(kWidevineKeySystem));
    EXPECT_CALL(m_openCdmSessionMock, initialize()).WillOnce(Return(true));
    EXPECT_CALL(m_openCdmSessionMock, generateRequest(kInitDataType, kInitData, kCdmData)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_construct_session(&m_openCdmSystemMock, kLicenseType, kInitDataType.c_str(),
                                                    kInitData.data(), kInitData.size(), kCdmData.data(),
                                                    kCdmData.size(), &m_callbacks, &m_userData, &resultSession));
    EXPECT_EQ(&m_openCdmSessionMock, resultSession);
}

TEST_F(OpenCdmTests, ShouldDestructSession)
{
    // ActiveSessions tested in its own tests
    EXPECT_EQ(ERROR_NONE, opencdm_destruct_session(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldFailToLoadSessionWhenItIsNull)
{
    EXPECT_EQ(ERROR_INVALID_SESSION, opencdm_session_load(nullptr));
}

TEST_F(OpenCdmTests, ShouldFailToLoadSessionWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, loadSession()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_load(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldLoadSession)
{
    EXPECT_CALL(m_openCdmSessionMock, loadSession()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_load(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldFailToReturnMetadataWhenOneOfParamsIsNull)
{
    uint16_t metadataSize{0};
    EXPECT_EQ(ERROR_FAIL, opencdm_session_metadata(&m_openCdmSessionMock, nullptr, nullptr));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_metadata(nullptr, nullptr, &metadataSize));
}

TEST_F(OpenCdmTests, ShouldReturnMetadata)
{
    uint16_t metadataSize{12};
    EXPECT_EQ(ERROR_NONE, opencdm_session_metadata(&m_openCdmSessionMock, nullptr, &metadataSize));
    EXPECT_EQ(0, metadataSize);
}

TEST_F(OpenCdmTests, ShouldNotReturnSessionIdWhenSessionIsNull)
{
    EXPECT_EQ(nullptr, opencdm_session_id(nullptr));
}

TEST_F(OpenCdmTests, ShouldReturnSessionId)
{
    EXPECT_CALL(m_openCdmSessionMock, getSessionId()).WillOnce(ReturnRef(kSessionId));
    EXPECT_EQ(kSessionId, std::string(opencdm_session_id(&m_openCdmSessionMock)));
}

TEST_F(OpenCdmTests, ShouldReturnBufferId)
{
    EXPECT_EQ(nullptr, opencdm_session_buffer_id(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldFailToCheckSessionKeyWhenSessionIsNull)
{
    EXPECT_EQ(0, opencdm_session_has_key_id(nullptr, 0, nullptr));
}

TEST_F(OpenCdmTests, ShouldCheckIfSessionContainsKey)
{
    EXPECT_CALL(m_openCdmSessionMock, containsKey(kInitData)).WillOnce(Return(true));
    EXPECT_NE(0, opencdm_session_has_key_id(&m_openCdmSessionMock, kInitData.size(), kInitData.data()));
}

TEST_F(OpenCdmTests, ShouldFailToCheckSessionStatusWhenSessionIsNull)
{
    EXPECT_EQ(InternalError, opencdm_session_status(nullptr, kInitData.data(), kInitData.size()));
    EXPECT_EQ(InternalError, opencdm_session_status(&m_openCdmSessionMock, nullptr, 0));
}

TEST_F(OpenCdmTests, ShouldCheckSessionStatus)
{
    constexpr KeyStatus kKeyStatus{Usable};
    EXPECT_CALL(m_openCdmSessionMock, status(kInitData)).WillOnce(Return(kKeyStatus));
    EXPECT_EQ(kKeyStatus, opencdm_session_status(&m_openCdmSessionMock, kInitData.data(), kInitData.size()));
}

TEST_F(OpenCdmTests, ShouldCheckSessionError)
{
    EXPECT_EQ(0, opencdm_session_error(&m_openCdmSessionMock, kInitData.data(), kInitData.size()));
}

TEST_F(OpenCdmTests, ShouldFailToCheckSessionSystemErrorWhenSessionIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_session_system_error(nullptr));
}

TEST_F(OpenCdmTests, ShouldCheckSessionSystemError)
{
    EXPECT_CALL(m_openCdmSessionMock, getLastDrmError()).WillOnce(Return(0));
    EXPECT_EQ(ERROR_NONE, opencdm_session_system_error(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldFailToUpdateSessionWhenItIsNull)
{
    EXPECT_EQ(ERROR_INVALID_SESSION, opencdm_session_update(nullptr, kInitData.data(), kInitData.size()));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_update(&m_openCdmSessionMock, nullptr, 0));
}

TEST_F(OpenCdmTests, ShouldFailToUpdateSessionWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, updateSession(kInitData)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_update(&m_openCdmSessionMock, kInitData.data(), kInitData.size()));
}

TEST_F(OpenCdmTests, ShouldUpdateSession)
{
    EXPECT_CALL(m_openCdmSessionMock, updateSession(kInitData)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_update(&m_openCdmSessionMock, kInitData.data(), kInitData.size()));
}

TEST_F(OpenCdmTests, ShouldFailToRemoveSessionWhenItIsNull)
{
    EXPECT_EQ(ERROR_INVALID_SESSION, opencdm_session_remove(nullptr));
}

TEST_F(OpenCdmTests, ShouldFailToRemoveSessionWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, removeSession()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_remove(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldRemoveSession)
{
    EXPECT_CALL(m_openCdmSessionMock, removeSession()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_remove(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldResetOutputProtection)
{
    EXPECT_EQ(ERROR_NONE, opencdm_session_resetoutputprotection(&m_openCdmSessionMock));
}

// function not declared in official interface (?)
OpenCDMError opencdm_session_set_parameter(struct OpenCDMSession *session, const std::string &name,
                                           const std::string &value);
TEST_F(OpenCdmTests, ShouldSetParameter)
{
    const std::string kName{"name"};
    const std::string kValue{"value"};
    EXPECT_EQ(ERROR_NONE, opencdm_session_set_parameter(&m_openCdmSessionMock, kName, kValue));
}

TEST_F(OpenCdmTests, ShouldFailToCloseSessionWhenItIsNull)
{
    EXPECT_EQ(ERROR_INVALID_SESSION, opencdm_session_close(nullptr));
}

TEST_F(OpenCdmTests, ShouldFailToCloseSessionWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, closeSession()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_close(&m_openCdmSessionMock));
}

TEST_F(OpenCdmTests, ShouldCloseSession)
{
    EXPECT_CALL(m_openCdmSessionMock, closeSession()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_close(&m_openCdmSessionMock));
}
