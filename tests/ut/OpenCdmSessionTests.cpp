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
#include "RialtoGStreamerEMEProtectionMetadata.h"
#include <MessageDispatcherClientMock.h>
#include <gst/gst.h>
#include <gtest/gtest.h>

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SetArgReferee;
using testing::StrictMock;

namespace
{
constexpr LicenseType kSessionType{LicenseType::Temporary};
constexpr firebolt::rialto::KeySessionType kRialtoSessionType{firebolt::rialto::KeySessionType::TEMPORARY};
const std::string kInitDataType{"drmheader"};
constexpr firebolt::rialto::InitDataType kRialtoInitDataType{firebolt::rialto::InitDataType::DRMHEADER};
const std::vector<uint8_t> kBytes1{1, 2, 3, 4};
const std::vector<uint8_t> kBytes2{4, 3, 2, 1};
const std::vector<uint8_t> kBytes3{5, 6, 7, 8};
const std::vector<uint8_t> kBytes4{8, 7, 6, 5};
constexpr bool kIsLdl{false};
constexpr int32_t kKeySessionId{14};
const std::string kUrl{"some.url"};
constexpr uint32_t kInitWithLast15{1};
const std::string kCipherMode{"ciphermode"};
constexpr uint32_t kPatternCryptoBlocks{14};
constexpr uint32_t kPatternClearBlocks{53};
constexpr firebolt::rialto::LimitedDurationLicense kLdlState{firebolt::rialto::LimitedDurationLicense::NOT_SPECIFIED};
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
    GstBuffer *m_buffer;
    GstBuffer *m_subSamples;
    GstBuffer *m_iv;
    GstBuffer *m_keyId;
    std::unique_ptr<OpenCDMSessionPrivate> m_sut;

    ~OpenCdmSessionTests() override
    {
        testing::Mock::VerifyAndClearExpectations(&OcdmSessionsCallbacksMock::instance());
    }

    void createSut(const LicenseType &licenseType = kSessionType)
    {
        m_sut = std::make_unique<OpenCDMSessionPrivate>(m_cdmBackendMock, m_messageDispatcherMock, licenseType,
                                                        &m_callbacks, &m_userData, kInitDataType, kBytes1);
    }

    void createInvalidSut()
    {
        m_sut = std::make_unique<OpenCDMSessionPrivate>(nullptr, nullptr, kSessionType, &m_callbacks, &m_userData,
                                                        kInitDataType, kBytes1);
    }

    void initializeSut(const firebolt::rialto::KeySessionType &sessionType = kRialtoSessionType)
    {
        EXPECT_CALL(*m_cdmBackendMock, createKeySession(sessionType, _))
            .WillOnce(DoAll(SetArgReferee<1>(kKeySessionId), Return(true)));
        EXPECT_CALL(*m_messageDispatcherMock, createClient(_))
            .WillOnce(Return(ByMove(std::make_unique<StrictMock<MessageDispatcherClientMock>>())));
        EXPECT_TRUE(m_sut->initialize());
    }

    void requestLicense()
    {
        EXPECT_CALL(OcdmSessionsCallbacksMock::instance(),
                    processChallengeCallback(m_sut.get(), &m_userData, kUrl.c_str(), kBytes1.data(), kBytes1.size()));
        m_sut->onLicenseRequest(kKeySessionId, kBytes1, kUrl);
    }

    void updateKeyStatus(const std::vector<uint8_t> &key, const firebolt::rialto::KeyStatus &status)
    {
        firebolt::rialto::KeyStatusVector statusVec{std::make_pair(key, status)};
        EXPECT_CALL(OcdmSessionsCallbacksMock::instance(),
                    keyUpdateCallback(m_sut.get(), &m_userData, statusVec[0].first.data(), statusVec[0].first.size()));
        EXPECT_CALL(OcdmSessionsCallbacksMock::instance(), keysUpdatedCallback(m_sut.get(), &m_userData));
        m_sut->onKeyStatusesChanged(kKeySessionId, statusVec);
    }

    void fillBuffers()
    {
        gst_init(nullptr, nullptr);
        m_buffer = gst_buffer_new_allocate(nullptr, kBytes1.size(), nullptr);
        m_subSamples = gst_buffer_new_allocate(nullptr, kBytes2.size(), nullptr);
        m_iv = gst_buffer_new_allocate(nullptr, kBytes3.size(), nullptr);
        m_keyId = gst_buffer_new_allocate(nullptr, kBytes4.size(), nullptr);
        gst_buffer_fill(m_buffer, 0, kBytes1.data(), kBytes1.size());
        gst_buffer_fill(m_subSamples, 0, kBytes2.data(), kBytes2.size());
        gst_buffer_fill(m_iv, 0, kBytes3.data(), kBytes3.size());
        gst_buffer_fill(m_keyId, 0, kBytes4.data(), kBytes4.size());
    }

    void cleanBuffers()
    {
        gst_buffer_unref(m_keyId);
        gst_buffer_unref(m_iv);
        gst_buffer_unref(m_subSamples);
        gst_buffer_unref(m_buffer);
    }

    void verifyMetadata()
    {
        GstRialtoProtectionMetadata *protectionMeta = reinterpret_cast<GstRialtoProtectionMetadata *>(
            gst_buffer_get_meta(m_buffer, GST_RIALTO_PROTECTION_METADATA_GET_TYPE));
        ASSERT_TRUE(protectionMeta);
        EXPECT_TRUE(g_value_get_boolean(gst_structure_get_value(protectionMeta->info, "encrypted")));
        EXPECT_EQ(g_value_get_int(gst_structure_get_value(protectionMeta->info, "mks_id")), kKeySessionId);
        EXPECT_EQ(g_value_get_uint(gst_structure_get_value(protectionMeta->info, "iv_size")), kBytes3.size());
        EXPECT_EQ(gst_value_get_buffer(gst_structure_get_value(protectionMeta->info, "iv")), m_iv);
        EXPECT_EQ(g_value_get_uint(gst_structure_get_value(protectionMeta->info, "subsample_count")), kBytes2.size());
        EXPECT_EQ(gst_value_get_buffer(gst_structure_get_value(protectionMeta->info, "subsamples")), m_subSamples);
        EXPECT_EQ(g_value_get_uint(gst_structure_get_value(protectionMeta->info, "encryption_scheme")), 0);
        EXPECT_EQ(g_value_get_uint(gst_structure_get_value(protectionMeta->info, "init_with_last_15")), kInitWithLast15);
        // Key has to be checked by value, as it may have different address
        GstMapInfo mapInfo;
        GstBuffer *keyBuffer = gst_value_get_buffer(gst_structure_get_value(protectionMeta->info, "kid"));
        ASSERT_TRUE(keyBuffer);
        ASSERT_TRUE(gst_buffer_map(keyBuffer, &mapInfo, GST_MAP_READ));
        EXPECT_EQ(std::vector<uint8_t>(mapInfo.data, mapInfo.data + mapInfo.size), kBytes4);
        gst_buffer_unmap(keyBuffer, &mapInfo);
    }

    void verifyMetadataAdditionalFields()
    {
        GstRialtoProtectionMetadata *protectionMeta = reinterpret_cast<GstRialtoProtectionMetadata *>(
            gst_buffer_get_meta(m_buffer, GST_RIALTO_PROTECTION_METADATA_GET_TYPE));
        ASSERT_TRUE(protectionMeta);
        EXPECT_EQ(std::string(g_value_get_string(gst_structure_get_value(protectionMeta->info, "cipher-mode"))),
                  kCipherMode);
        EXPECT_EQ(g_value_get_uint(gst_structure_get_value(protectionMeta->info, "crypt_byte_block")),
                  kPatternCryptoBlocks);
        EXPECT_EQ(g_value_get_uint(gst_structure_get_value(protectionMeta->info, "skip_byte_block")),
                  kPatternClearBlocks);
    }

    void addGstProtectionMeta()
    {
        GstStructure *info =
            gst_structure_new("application/x-cenc", "kid", GST_TYPE_BUFFER, m_keyId, "iv", GST_TYPE_BUFFER, m_iv,
                              "subsample_count", G_TYPE_UINT, kBytes2.size(), "subsamples", GST_TYPE_BUFFER,
                              m_subSamples, "init_with_last_15", G_TYPE_UINT, kInitWithLast15, "cipher-mode",
                              G_TYPE_STRING, kCipherMode.c_str(), "crypt_byte_block", G_TYPE_UINT, kPatternCryptoBlocks,
                              "skip_byte_block", G_TYPE_UINT, kPatternClearBlocks, NULL);
        gst_buffer_add_protection_meta(m_buffer, info);
    }

    void teardownSut() { EXPECT_CALL(*m_cdmBackendMock, releaseKeySession(kKeySessionId)).WillOnce(Return(true)); }
};

TEST_F(OpenCdmSessionTests, ShouldNotInitializeWhenBackendOrDispatcherIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->initialize());
}

TEST_F(OpenCdmSessionTests, ShouldNotInitializeWhenCreateKeySessionFails)
{
    createSut();
    EXPECT_CALL(*m_cdmBackendMock, createKeySession(kRialtoSessionType, _)).WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(_, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->initialize());
}

TEST_F(OpenCdmSessionTests, ShouldInitialize)
{
    createSut();
    initializeSut();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldInitializeWithAllPossibleLicenseTypes)
{
    createSut(LicenseType::PersistentUsageRecord);
    initializeSut(firebolt::rialto::KeySessionType::UNKNOWN);
    teardownSut();

    createSut(LicenseType::PersistentLicense);
    initializeSut(firebolt::rialto::KeySessionType::PERSISTENT_LICENCE);
    teardownSut();

    createSut(static_cast<LicenseType>(7)); // some uknown license type
    initializeSut(firebolt::rialto::KeySessionType::UNKNOWN);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotInitializeTwice)
{
    createSut();
    initializeSut();
    EXPECT_TRUE(m_sut->initialize());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->generateRequest(kInitDataType, kBytes1, kBytes2));
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenInitDataTypeIsUnknown)
{
    createSut();
    EXPECT_FALSE(m_sut->generateRequest("surprise", kBytes1, kBytes2));
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->generateRequest(kInitDataType, kBytes1, kBytes2));
}

TEST_F(OpenCdmSessionTests, ShouldNotGenerateRequestWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1, kLdlState))
        .WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->generateRequest(kInitDataType, kBytes1, kBytes2));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldGenerateRequest)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1, kLdlState))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest(kInitDataType, kBytes1, kBytes2));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldGenerateRequestForAllInitDataTypes)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock,
                generateRequest(kKeySessionId, firebolt::rialto::InitDataType::CENC, kBytes1, kLdlState))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest("cenc", kBytes1, kBytes2));

    EXPECT_CALL(*m_cdmBackendMock,
                generateRequest(kKeySessionId, firebolt::rialto::InitDataType::WEBM, kBytes1, kLdlState))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest("webm", kBytes1, kBytes2));
    teardownSut();
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
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldLoadSession)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, loadSession(kKeySessionId)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->loadSession());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotUpdateSessionWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->updateSession(kBytes1));
}

TEST_F(OpenCdmSessionTests, ShouldNotUpdateSessionWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->updateSession(kBytes1));
}

TEST_F(OpenCdmSessionTests, ShouldFailToUpdateSessionWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, updateSession(kKeySessionId, kBytes1)).WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->updateSession(kBytes1));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldUpdateSession)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, updateSession(kKeySessionId, kBytes1)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->updateSession(kBytes1));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotGetChallengeDataWhenNotInitialized)
{
    std::vector<uint8_t> challengeData{};
    createSut();
    EXPECT_FALSE(m_sut->getChallengeData(challengeData, kIsLdl));
}

TEST_F(OpenCdmSessionTests, ShouldGetChallengeData)
{
    std::vector<uint8_t> challengeData{};
    uint32_t challengeDataSize{0};
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1,
                                                   firebolt::rialto::LimitedDurationLicense::DISABLED))
        .WillOnce(Invoke(
            [&](int32_t, firebolt::rialto::InitDataType, const std::vector<uint8_t> &,
                firebolt::rialto::LimitedDurationLicense)
            {
                requestLicense();
                return true;
            }));
    EXPECT_TRUE(m_sut->getChallengeDataSize(challengeDataSize, kIsLdl));
    EXPECT_EQ(challengeDataSize, kBytes1.size());

    EXPECT_TRUE(m_sut->getChallengeData(challengeData, kIsLdl));
    EXPECT_EQ(challengeData, kBytes1);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotGetChallengeDataSizeWhenCdmBackendIsNull)
{
    uint32_t challengeDataSize{0};
    createInvalidSut();
    EXPECT_FALSE(m_sut->getChallengeDataSize(challengeDataSize, kIsLdl));
}

TEST_F(OpenCdmSessionTests, ShouldNotGetChallengeDataSizeWhenNotInitialized)
{
    uint32_t challengeDataSize{0};
    createSut();
    EXPECT_FALSE(m_sut->getChallengeDataSize(challengeDataSize, kIsLdl));
}

TEST_F(OpenCdmSessionTests, ShouldFailToGetChallengeDataSizeWhenOperationFails)
{
    uint32_t challengeDataSize{0};
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1,
                                                   firebolt::rialto::LimitedDurationLicense::DISABLED))
        .WillOnce(Return(false));
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->getChallengeDataSize(challengeDataSize, kIsLdl));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldGetChallengeDataSize)
{
    uint32_t challengeDataSize{0};
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1,
                                                   firebolt::rialto::LimitedDurationLicense::DISABLED))
        .WillOnce(Invoke(
            [&](int32_t, firebolt::rialto::InitDataType, const std::vector<uint8_t> &,
                firebolt::rialto::LimitedDurationLicense)
            {
                requestLicense();
                return true;
            }));
    EXPECT_TRUE(m_sut->getChallengeDataSize(challengeDataSize, kIsLdl));
    EXPECT_EQ(challengeDataSize, kBytes1.size());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldAddBasicProtectionMeta)
{
    fillBuffers();
    createSut();
    initializeSut();

    m_sut->addProtectionMeta(m_buffer, m_subSamples, kBytes2.size(), m_iv, m_keyId, kInitWithLast15);

    verifyMetadata();
    cleanBuffers();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldAddBasicProtectionMetaWithPlayreadyKey)
{
    fillBuffers();
    createSut();
    initializeSut();
    // Reset keyId buffer
    gst_buffer_unref(m_keyId);
    m_keyId = gst_buffer_new();
    // Set Playready key in sut
    m_sut->selectKeyId(kBytes4);

    m_sut->addProtectionMeta(m_buffer, m_subSamples, kBytes2.size(), m_iv, m_keyId, kInitWithLast15);

    verifyMetadata();
    cleanBuffers();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldAddProtectionMetaWithAdditionalFields)
{
    fillBuffers();
    addGstProtectionMeta();

    createSut();
    initializeSut();

    m_sut->addProtectionMeta(m_buffer, m_subSamples, kBytes2.size(), m_iv, m_keyId, kInitWithLast15);

    verifyMetadata();
    verifyMetadataAdditionalFields();
    cleanBuffers();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotAddProtectionMetaWhenGstProtectionMetaIsNotPresent)
{
    fillBuffers();

    createSut();
    initializeSut();

    EXPECT_FALSE(m_sut->addProtectionMeta(m_buffer));

    cleanBuffers();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldAddProtectionMetaFromGstProtectionMeta)
{
    fillBuffers();
    addGstProtectionMeta();

    createSut();
    initializeSut();

    EXPECT_TRUE(m_sut->addProtectionMeta(m_buffer));

    verifyMetadata();
    verifyMetadataAdditionalFields();
    cleanBuffers();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldAddProtectionMetaFromGstProtectionMetaWithPlayreadyKey)
{
    fillBuffers();
    addGstProtectionMeta();

    createSut();
    initializeSut();

    m_sut->selectKeyId(kBytes4);
    EXPECT_TRUE(m_sut->addProtectionMeta(m_buffer));

    verifyMetadata();
    verifyMetadataAdditionalFields();
    cleanBuffers();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotCloseSessionWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->closeSession());
}

TEST_F(OpenCdmSessionTests, ShouldNotCloseSessionWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->closeSession());
}

TEST_F(OpenCdmSessionTests, ShouldFailToCloseSessionWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, closeKeySession(kKeySessionId)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->closeSession());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldCloseSession)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, closeKeySession(kKeySessionId)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->closeSession());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotRemoveSessionWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->removeSession());
}

TEST_F(OpenCdmSessionTests, ShouldNotRemoveSessionWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->removeSession());
}

TEST_F(OpenCdmSessionTests, ShouldFailToRemoveSessionWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, removeKeySession(kKeySessionId)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->removeSession());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldRemoveSession)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, removeKeySession(kKeySessionId)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->removeSession());
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotContainKeyWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->containsKey(kBytes1));
}

TEST_F(OpenCdmSessionTests, ShouldNotContainKeyWhenNotInitialized)
{
    createSut();
    EXPECT_FALSE(m_sut->containsKey(kBytes1));
}

TEST_F(OpenCdmSessionTests, ShouldNotContainKeyWhenOperationReturnsFalse)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, containsKey(kKeySessionId, kBytes1)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->containsKey(kBytes1));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldContainKey)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, containsKey(kKeySessionId, kBytes1)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->containsKey(kBytes1));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotSetDrmHeaderWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_FALSE(m_sut->setDrmHeader(kBytes1));
}

TEST_F(OpenCdmSessionTests, ShouldQueueDrmHeaderWhenNotInitialized)
{
    createSut();
    EXPECT_TRUE(m_sut->setDrmHeader(kBytes1));
    EXPECT_CALL(*m_cdmBackendMock, setDrmHeader(kKeySessionId, kBytes1)).WillOnce(Return(true));
    initializeSut();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldFailToSetQueuedDrmHeader)
{
    createSut();
    EXPECT_TRUE(m_sut->setDrmHeader(kBytes1));
    EXPECT_CALL(*m_cdmBackendMock, setDrmHeader(kKeySessionId, kBytes1)).WillOnce(Return(false));
    initializeSut();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldFailToSetDrmHeaderWhenOperationFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, setDrmHeader(kKeySessionId, kBytes1)).WillOnce(Return(false));
    EXPECT_FALSE(m_sut->setDrmHeader(kBytes1));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldSetDrmHeader)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, setDrmHeader(kKeySessionId, kBytes1)).WillOnce(Return(true));
    EXPECT_TRUE(m_sut->setDrmHeader(kBytes1));
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotProcessLicenseRequestWhenNotInitialized)
{
    createSut();
    m_sut->onLicenseRequest(kKeySessionId, kBytes1, kUrl);
}

TEST_F(OpenCdmSessionTests, ShouldProcessLicenseRequest)
{
    createSut();
    initializeSut();
    requestLicense();
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotProcessLicenseRenewalWhenNotInitialized)
{
    createSut();
    m_sut->onLicenseRenewal(kKeySessionId, kBytes1);
}

TEST_F(OpenCdmSessionTests, ShouldProcessLicenseRenewal)
{
    createSut();
    initializeSut();
    EXPECT_CALL(OcdmSessionsCallbacksMock::instance(),
                processChallengeCallback(m_sut.get(), &m_userData, _, kBytes1.data(), kBytes1.size()));
    m_sut->onLicenseRenewal(kKeySessionId, kBytes1);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldNotProcessKeyStatusUpdateWhenNotInitialized)
{
    createSut();
    m_sut->onKeyStatusesChanged(kKeySessionId, {});
}

TEST_F(OpenCdmSessionTests, ShouldProcessKeyStatusUpdates)
{
    createSut();
    initializeSut();
    updateKeyStatus(kBytes1, firebolt::rialto::KeyStatus::USABLE);
    EXPECT_EQ(m_sut->status(kBytes1), Usable);
    updateKeyStatus(kBytes1, firebolt::rialto::KeyStatus::EXPIRED);
    EXPECT_EQ(m_sut->status(kBytes1), Expired);
    updateKeyStatus(kBytes1, firebolt::rialto::KeyStatus::OUTPUT_RESTRICTED);
    EXPECT_EQ(m_sut->status(kBytes1), OutputRestricted);
    updateKeyStatus(kBytes1, firebolt::rialto::KeyStatus::PENDING);
    EXPECT_EQ(m_sut->status(kBytes1), StatusPending);
    updateKeyStatus(kBytes1, firebolt::rialto::KeyStatus::INTERNAL_ERROR);
    EXPECT_EQ(m_sut->status(kBytes1), InternalError);
    updateKeyStatus(kBytes1, firebolt::rialto::KeyStatus::RELEASED);
    EXPECT_EQ(m_sut->status(kBytes1), Released);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldReturnInternalErrorForUnknownKey)
{
    createSut();
    initializeSut();
    EXPECT_EQ(m_sut->status(kBytes1), InternalError);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldReturnEmptySessionIdWhenNotInitialized)
{
    createSut();
    EXPECT_EQ(m_sut->getSessionId(), "");
}

TEST_F(OpenCdmSessionTests, ShouldReturnDefaultSessionIdWhenGetCdmKeySessionIdFails)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1, kLdlState))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _)).WillOnce(Return(false));
    EXPECT_TRUE(m_sut->generateRequest(kInitDataType, kBytes1, kBytes2));
    EXPECT_EQ(m_sut->getSessionId(), "0");
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldReturnSessionId)
{
    const std::string cdmSessionId{"id"};
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, generateRequest(kKeySessionId, kRialtoInitDataType, kBytes1, kLdlState))
        .WillOnce(Return(true));
    EXPECT_CALL(*m_cdmBackendMock, getCdmKeySessionId(kKeySessionId, _))
        .WillOnce(DoAll(SetArgReferee<1>(cdmSessionId), Return(true)));
    EXPECT_TRUE(m_sut->generateRequest(kInitDataType, kBytes1, kBytes2));
    EXPECT_EQ(m_sut->getSessionId(), cdmSessionId);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, ShouldFailToReturnLastDrmErrorWhenCdmBackendIsNull)
{
    createInvalidSut();
    EXPECT_EQ(m_sut->getLastDrmError(), -1);
}

TEST_F(OpenCdmSessionTests, ShouldReturnLastDrmError)
{
    constexpr uint32_t kError{13};
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, getLastDrmError(kKeySessionId, _))
        .WillOnce(DoAll(SetArgReferee<1>(kError), Return(true)));
    EXPECT_EQ(m_sut->getLastDrmError(), kError);
    teardownSut();
}

TEST_F(OpenCdmSessionTests, TeardownFailure)
{
    createSut();
    initializeSut();
    EXPECT_CALL(*m_cdmBackendMock, releaseKeySession(kKeySessionId)).WillOnce(Return(false));
}
