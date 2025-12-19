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
#include "OpenCDMSystemMock.h"
#include "opencdm/open_cdm_ext.h"
#include <gtest/gtest.h>

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgReferee;
using testing::StrictMock;

namespace
{
const std::vector<uint8_t> kBytes{1, 2, 3, 4};
constexpr uint32_t kIsLdl{1};
} // namespace

class OpenCdmExtTests : public testing::Test
{
protected:
    StrictMock<OpenCDMSystemMock> m_openCdmSystemMock;
    StrictMock<OpenCDMSessionMock> m_openCdmSessionMock;
};

TEST_F(OpenCdmExtTests, ShouldFailToGetLdlSessionLimitWhenOneOfParamsIsNull)
{
    uint32_t limit{0};
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_get_ldl_session_limit(nullptr, &limit));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_get_ldl_session_limit(&m_openCdmSystemMock, nullptr));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetLdlSessionLimitWhenoperationFails)
{
    uint32_t limit{0};
    EXPECT_CALL(m_openCdmSystemMock, getLdlSessionsLimit(_)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_get_ldl_session_limit(&m_openCdmSystemMock, &limit));
}

TEST_F(OpenCdmExtTests, ShouldGetLdlSessionLimit)
{
    constexpr uint32_t kResultLimit{12};
    uint32_t limit{0};
    EXPECT_CALL(m_openCdmSystemMock, getLdlSessionsLimit(_)).WillOnce(DoAll(SetArgReferee<0>(kResultLimit), Return(true)));
    EXPECT_EQ(ERROR_NONE, opencdm_system_ext_get_ldl_session_limit(&m_openCdmSystemMock, &limit));
    EXPECT_EQ(kResultLimit, limit);
}

TEST_F(OpenCdmExtTests, SecureStopShouldBeDisabled)
{
    EXPECT_EQ(0, opencdm_system_ext_is_secure_stop_enabled(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldFailToEnableSecureStop)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_enable_secure_stop(&m_openCdmSystemMock, 1));
}

TEST_F(OpenCdmExtTests, ShouldFailToResetSecureStop)
{
    EXPECT_EQ(0, opencdm_system_ext_reset_secure_stop(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetSecureStopIds)
{
    uint32_t count{0};
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_get_secure_stop_ids(&m_openCdmSystemMock, nullptr, 0, &count));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetSecureStop)
{
    uint16_t size{0};
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_get_secure_stop(&m_openCdmSystemMock, nullptr, 0, nullptr, &size));
}

TEST_F(OpenCdmExtTests, ShouldFailToCommitSecureStop)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_system_ext_commit_secure_stop(&m_openCdmSystemMock, nullptr, 0, nullptr, 0));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetKeyStoreHashWhenOneOfParamsIsNull)
{
    std::vector<uint8_t> resultBytes{0, 0, 0, 0};
    EXPECT_EQ(ERROR_FAIL, opencdm_get_key_store_hash_ext(nullptr, resultBytes.data(), resultBytes.size()));
    EXPECT_EQ(ERROR_FAIL, opencdm_get_key_store_hash_ext(&m_openCdmSystemMock, nullptr, 0));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetKeyStoreHashWhenOperationFails)
{
    std::vector<uint8_t> resultBytes{0, 0, 0, 0};
    EXPECT_CALL(m_openCdmSystemMock, getKeyStoreHash(_)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_get_key_store_hash_ext(&m_openCdmSystemMock, resultBytes.data(), resultBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetKeyStoreHashResultsSizeIsTooBig)
{
    std::vector<uint8_t> resultBytes{0, 0, 0};
    EXPECT_CALL(m_openCdmSystemMock, getKeyStoreHash(_)).WillOnce(DoAll(SetArgReferee<0>(kBytes), Return(true)));
    EXPECT_EQ(ERROR_FAIL, opencdm_get_key_store_hash_ext(&m_openCdmSystemMock, resultBytes.data(), resultBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldGetKeyStoreHash)
{
    std::vector<uint8_t> resultBytes{0, 0, 0, 0};
    EXPECT_CALL(m_openCdmSystemMock, getKeyStoreHash(_)).WillOnce(DoAll(SetArgReferee<0>(kBytes), Return(true)));
    EXPECT_EQ(ERROR_NONE, opencdm_get_key_store_hash_ext(&m_openCdmSystemMock, resultBytes.data(), resultBytes.size()));
    EXPECT_EQ(resultBytes, kBytes);
}

TEST_F(OpenCdmExtTests, ShouldFailToGetSecureStoreHashWhenOneOfParamsIsNull)
{
    std::vector<uint8_t> resultBytes{0, 0, 0, 0};
    EXPECT_EQ(ERROR_FAIL, opencdm_get_secure_store_hash_ext(nullptr, resultBytes.data(), resultBytes.size()));
    EXPECT_EQ(ERROR_FAIL, opencdm_get_secure_store_hash_ext(&m_openCdmSystemMock, nullptr, 0));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetSecureStoreHashWhenOperationFails)
{
    std::vector<uint8_t> resultBytes{0, 0, 0, 0};
    EXPECT_CALL(m_openCdmSystemMock, getDrmStoreHash(_)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL,
              opencdm_get_secure_store_hash_ext(&m_openCdmSystemMock, resultBytes.data(), resultBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetSecureStoreHashResultsSizeIsTooBig)
{
    std::vector<uint8_t> resultBytes{0, 0, 0};
    EXPECT_CALL(m_openCdmSystemMock, getDrmStoreHash(_)).WillOnce(DoAll(SetArgReferee<0>(kBytes), Return(true)));
    EXPECT_EQ(ERROR_FAIL,
              opencdm_get_secure_store_hash_ext(&m_openCdmSystemMock, resultBytes.data(), resultBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldGetSecureStoreHash)
{
    std::vector<uint8_t> resultBytes{0, 0, 0, 0};
    EXPECT_CALL(m_openCdmSystemMock, getDrmStoreHash(_)).WillOnce(DoAll(SetArgReferee<0>(kBytes), Return(true)));
    EXPECT_EQ(ERROR_NONE,
              opencdm_get_secure_store_hash_ext(&m_openCdmSystemMock, resultBytes.data(), resultBytes.size()));
    EXPECT_EQ(resultBytes, kBytes);
}

TEST_F(OpenCdmExtTests, ShouldFailToDeleteKeyStoreWhenOneOfParamsIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_delete_key_store(nullptr));
}

TEST_F(OpenCdmExtTests, ShouldFailToDeleteKeyStoreWhenoperationFails)
{
    EXPECT_CALL(m_openCdmSystemMock, deleteKeyStore()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_delete_key_store(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldDeleteKeyStore)
{
    EXPECT_CALL(m_openCdmSystemMock, deleteKeyStore()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_delete_key_store(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldFailToDeleteSecureStoreWhenOneOfParamsIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_delete_secure_store(nullptr));
}

TEST_F(OpenCdmExtTests, ShouldFailToDeleteSecureStoreWhenoperationFails)
{
    EXPECT_CALL(m_openCdmSystemMock, deleteDrmStore()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_delete_secure_store(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldDeleteSecureStore)
{
    EXPECT_CALL(m_openCdmSystemMock, deleteDrmStore()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_delete_secure_store(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldFailToSetDrmHeaderWhenOneOfParamsIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_session_set_drm_header(nullptr, kBytes.data(), kBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldFailToSetDrmHeaderWhenoperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, setDrmHeader(kBytes)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_set_drm_header(&m_openCdmSessionMock, kBytes.data(), kBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldSetDrmHeader)
{
    EXPECT_CALL(m_openCdmSessionMock, setDrmHeader(kBytes)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_set_drm_header(&m_openCdmSessionMock, kBytes.data(), kBytes.size()));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetChallengeDataWhenOneOfParamsIsNull)
{
    std::vector<uint8_t> challengeVec{1, 2, 3};
    uint32_t challengeSize{static_cast<uint32_t>(challengeVec.size())};
    EXPECT_EQ(ERROR_FAIL, opencdm_session_get_challenge_data(nullptr, challengeVec.data(), &challengeSize, kIsLdl));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_get_challenge_data(&m_openCdmSessionMock, nullptr, nullptr, kIsLdl));
}

TEST_F(OpenCdmExtTests, ShouldFailToGetChallengeDataWhenGetChallengeDataFails)
{
    uint32_t challengeSize{0};
    EXPECT_CALL(m_openCdmSessionMock, getChallengeDataSize(_, kIsLdl)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_get_challenge_data(&m_openCdmSessionMock, nullptr, &challengeSize, kIsLdl));
}

TEST_F(OpenCdmExtTests, ShouldGetChallengeDataAndSize)
{
    uint32_t challengeSize{0};
    EXPECT_CALL(m_openCdmSessionMock, getChallengeDataSize(_, kIsLdl))
        .WillOnce(DoAll(SetArgReferee<0>(kBytes.size()), Return(true)));
    EXPECT_EQ(ERROR_NONE, opencdm_session_get_challenge_data(&m_openCdmSessionMock, nullptr, &challengeSize, kIsLdl));
    EXPECT_EQ(kBytes.size(), challengeSize);

    // Second call should get the cached data only
    std::vector<uint8_t> challengeVec(kBytes.size(), 0);
    EXPECT_CALL(m_openCdmSessionMock, getChallengeData(_, kIsLdl)).WillOnce(DoAll(SetArgReferee<0>(kBytes), Return(true)));
    EXPECT_EQ(ERROR_NONE,
              opencdm_session_get_challenge_data(&m_openCdmSessionMock, challengeVec.data(), &challengeSize, kIsLdl));
    EXPECT_EQ(kBytes.size(), challengeSize);
    EXPECT_EQ(kBytes, challengeVec);
}

TEST_F(OpenCdmExtTests, ShouldCancelChallengeData)
{
    EXPECT_EQ(ERROR_NONE, opencdm_session_cancel_challenge_data(&m_openCdmSessionMock));
}

TEST_F(OpenCdmExtTests, ShouldFailToStoreLicenseDataWhenOneOfParamsIsNull)
{
    uint8_t secureStopId{0};
    EXPECT_EQ(ERROR_INVALID_SESSION,
              opencdm_session_store_license_data(nullptr, kBytes.data(), kBytes.size(), &secureStopId));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_store_license_data(&m_openCdmSessionMock, nullptr, 0, &secureStopId));
}

TEST_F(OpenCdmExtTests, ShouldFailToStoreLicenseDataWhenOperationFails)
{
    uint8_t secureStopId{0};
    EXPECT_CALL(m_openCdmSessionMock, updateSession(kBytes)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL,
              opencdm_session_store_license_data(&m_openCdmSessionMock, kBytes.data(), kBytes.size(), &secureStopId));
}

TEST_F(OpenCdmExtTests, ShouldStoreLicenseData)
{
    uint8_t secureStopId{0};
    EXPECT_CALL(m_openCdmSessionMock, updateSession(kBytes)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE,
              opencdm_session_store_license_data(&m_openCdmSessionMock, kBytes.data(), kBytes.size(), &secureStopId));
}

TEST_F(OpenCdmExtTests, ShouldFailToSelectKeyIdWhenOneOfParamsIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_session_select_key_id(&m_openCdmSessionMock, 0, nullptr));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_select_key_id(nullptr, kBytes.size(), kBytes.data()));
}

TEST_F(OpenCdmExtTests, ShouldFailToSelectKeyIdWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, selectKeyId(kBytes)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_select_key_id(&m_openCdmSessionMock, kBytes.size(), kBytes.data()));
}

TEST_F(OpenCdmExtTests, ShouldSelectKeyId)
{
    EXPECT_CALL(m_openCdmSessionMock, selectKeyId(kBytes)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_select_key_id(&m_openCdmSessionMock, kBytes.size(), kBytes.data()));
}

TEST_F(OpenCdmExtTests, ShouldTeardown)
{
    EXPECT_EQ(ERROR_NONE, opencdm_system_teardown(&m_openCdmSystemMock));
}

TEST_F(OpenCdmExtTests, ShouldFailToCleanDecryptContextWhenOneOfParamsIsNull)
{
    EXPECT_EQ(ERROR_FAIL, opencdm_session_clean_decrypt_context(nullptr));
}

TEST_F(OpenCdmExtTests, ShouldFailToCleanDecryptContextWhenOperationFails)
{
    EXPECT_CALL(m_openCdmSessionMock, closeSession()).WillOnce(Return(false));
    EXPECT_EQ(ERROR_FAIL, opencdm_session_clean_decrypt_context(&m_openCdmSessionMock));
}

TEST_F(OpenCdmExtTests, ShouldCleanDecryptContext)
{
    EXPECT_CALL(m_openCdmSessionMock, closeSession()).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, opencdm_session_clean_decrypt_context(&m_openCdmSessionMock));
}
