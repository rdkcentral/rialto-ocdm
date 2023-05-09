/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 Sky UK
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

#include "OpenCDMSession.h"
#include "RialtoGStreamerEMEProtectionMetadata.h"
#include <WPEFramework/core/Trace.h>
#include <gst/base/base.h>
#include <gst/gst.h>
#include <gst/gstprotection.h>

namespace
{
const KeyStatus convertKeyStatus(const firebolt::rialto::KeyStatus &keyStatus)
{
    switch (keyStatus)
    {
    case firebolt::rialto::KeyStatus::USABLE:
    {
        return Usable;
    }
    case firebolt::rialto::KeyStatus::EXPIRED:
    {
        return Expired;
    }
    case firebolt::rialto::KeyStatus::RELEASED:
    {
        return Released;
    }
    case firebolt::rialto::KeyStatus::OUTPUT_RESTRICTED:
    {
        return OutputRestricted;
    }
    case firebolt::rialto::KeyStatus::PENDING:
    {
        return StatusPending;
    }
    case firebolt::rialto::KeyStatus::INTERNAL_ERROR:
    default:
    {
        return InternalError;
    }
    }
}

const std::string kDefaultSessionId{"0"};
} // namespace

OpenCDMSession::OpenCDMSession(const std::shared_ptr<ICdmBackend> &cdm,
                               const std::shared_ptr<IMessageDispatcher> &messageDispatcher, const std::string &keySystem,
                               const LicenseType &sessionType, OpenCDMSessionCallbacks *callbacks, void *context,
                               const std::string &initDataType, const std::vector<uint8_t> &initData)
    : mContext(context), mCdmBackend(cdm), mMessageDispatcher(messageDispatcher), mKeySystem(keySystem),
      mRialtoSessionId(firebolt::rialto::kInvalidSessionId), mCallbacks(callbacks),
      mSessionType(getRialtoSessionType(sessionType)), mInitDataType(getRialtoInitDataType(initDataType)),
      mInitData(initData), mIsInitialized{false}
{
}

OpenCDMSession::~OpenCDMSession() {}

bool OpenCDMSession::initialize()
{
    if (!mCdmBackend || !mMessageDispatcher)
    {
        TRACE_L1("Cdm/message dispatcher is NULL or not initialized");
        return false;
    }
    if (!mIsInitialized)
    {
        if (!mCdmBackend->createKeySession(mSessionType, false, mRialtoSessionId))
        {
            TRACE_L1("Failed to create a session. Got status %u and drm error %u", static_cast<unsigned int>(status),
                     getLastDrmError());
            return false;
        }
        mMessageDispatcherClient = mMessageDispatcher->createClient(this);
        mIsInitialized = true;
        TRACE_L2("Successfully created a session");
    }
    return true;
}

bool OpenCDMSession::initialize(bool isLDL)
{
    if (!mCdmBackend || !mMessageDispatcher)
    {
        TRACE_L1("Cdm/message dispatcher is NULL or not initialized");
        return false;
    }
    if (!mIsInitialized)
    {
        if (!mCdmBackend->createKeySession(mSessionType, isLDL, mRialtoSessionId))
        {
            TRACE_L1("Failed to create a session. Got status %u and drm error %u", static_cast<unsigned int>(status),
                     getLastDrmError());
            return false;
        }
        mMessageDispatcherClient = mMessageDispatcher->createClient(this);
        mIsInitialized = true;
        TRACE_L2("Successfully created a session");
    }
    return true;
}

bool OpenCDMSession::generateRequest(const std::string &initDataType, const std::vector<uint8_t> &initData,
                                     const std::vector<uint8_t> &cdmData)
{
    bool result = false;
    firebolt::rialto::InitDataType dataType = getRialtoInitDataType(initDataType);
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if ((dataType != firebolt::rialto::InitDataType::UNKNOWN) && (-1 != mRialtoSessionId))
    {
        if (mCdmBackend->generateRequest(mRialtoSessionId, dataType, initData))
        {
            TRACE_L2("Successfully generated the request for the session");
            initializeCdmKeySessionId();
            result = true;
        }
        else
        {
            TRACE_L1("Failed to request for the session. Got status %u and drm error %u",
                     static_cast<unsigned int>(status), getLastDrmError());
        }
    }

    return result;
}

bool OpenCDMSession::loadSession()
{
    bool result = false;
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        if (mCdmBackend->loadSession(mRialtoSessionId))
        {
            TRACE_L2("Successfully loaded the session");
            result = true;
        }
        else
        {
            TRACE_L1("Failed to load the session. Got status %u and drm error %u", static_cast<unsigned int>(status),
                     getLastDrmError());
        }
    }

    return result;
}

bool OpenCDMSession::updateSession(const std::vector<uint8_t> &license)
{
    bool result = false;
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        if (mCdmBackend->updateSession(mRialtoSessionId, license))
        {
            TRACE_L2("Successfully updated the session");
            result = true;
        }
        else
        {
            TRACE_L1("Failed to update the session. Got status %u and drm error %u", static_cast<unsigned int>(status),
                     getLastDrmError());
        }
    }

    return result;
}

bool OpenCDMSession::getChallengeData(std::vector<uint8_t> &challengeData)
{
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }
    if ((mInitDataType != firebolt::rialto::InitDataType::UNKNOWN) && (-1 != mRialtoSessionId))
    {
        if (mCdmBackend->generateRequest(mRialtoSessionId, mInitDataType, mInitData))
        {
            TRACE_L2("Successfully generated the request for the session");
            initializeCdmKeySessionId();
        }
        else
        {
            TRACE_L1("Failed to request for the session. Got status %u and drm error %u",
                     static_cast<unsigned int>(status), getLastDrmError());
            return false;
        }
    }
    else
    {
        return false;
    }
    std::unique_lock<std::mutex> lock{mMutex};
    mChallengeCv.wait(lock, [this]() { return !mChallengeData.empty(); });
    challengeData = mChallengeData;
    return true;
}

void OpenCDMSession::addProtectionMeta(GstBuffer *buffer, GstBuffer *subSample, const uint32_t subSampleCount,
                                       GstBuffer *IV, GstBuffer *keyID, uint32_t initWithLast15)
{

    GstStructure *info = gst_structure_new("application/x-cenc", "encrypted", G_TYPE_BOOLEAN, TRUE, "mks_id", G_TYPE_INT,
                                           mRialtoSessionId, "kid", GST_TYPE_BUFFER, keyID, "iv_size", G_TYPE_UINT,
                                           gst_buffer_get_size(IV), "iv", GST_TYPE_BUFFER, IV, "subsample_count",
                                           G_TYPE_UINT, subSampleCount, "subsamples", GST_TYPE_BUFFER, subSample,
                                           "encryption_scheme", G_TYPE_UINT, 0, // AES Counter
                                           "init_with_last_15", G_TYPE_UINT, initWithLast15, NULL);

    GstProtectionMeta *protectionMeta = reinterpret_cast<GstProtectionMeta *>(gst_buffer_get_protection_meta(buffer));
    if (protectionMeta && protectionMeta->info)
    {
        const char *cipherModeBuf = gst_structure_get_string(protectionMeta->info, "cipher-mode");
        if (cipherModeBuf)
        {
            GST_INFO("Copy cipher mode [%s] and crypt/skipt byte blocks to protection metadata.", cipherModeBuf);
            gst_structure_set(info, "cipher-mode", G_TYPE_STRING, cipherModeBuf, NULL);

            uint32_t patternCryptoBlocks = 0;
            uint32_t patternClearBlocks = 0;

            if (gst_structure_get_uint(protectionMeta->info, "crypt_byte_block", &patternCryptoBlocks))
            {
                gst_structure_set(info, "crypt_byte_block", G_TYPE_UINT, patternCryptoBlocks, NULL);
            }

            if (gst_structure_get_uint(protectionMeta->info, "skip_byte_block", &patternClearBlocks))
            {
                gst_structure_set(info, "skip_byte_block", G_TYPE_UINT, patternClearBlocks, NULL);
            }
        }
    }

    rialto_mse_add_protection_metadata(buffer, info);
}

bool OpenCDMSession::addProtectionMeta(GstBuffer *buffer)
{
    GstProtectionMeta *protectionMeta = reinterpret_cast<GstProtectionMeta *>(gst_buffer_get_protection_meta(buffer));
    if (!protectionMeta)
    {
        TRACE_L1("No protection meta added to the buffer");
        return false;
    }

    GstStructure *info = gst_structure_copy(protectionMeta->info);
    gst_structure_set(info, "mks_id", G_TYPE_INT, mRialtoSessionId, NULL);

    if (!gst_structure_has_field_typed(info, "encrypted", G_TYPE_BOOLEAN))
    {
        // Set encrypted
        gst_structure_set(info, "encrypted", G_TYPE_BOOLEAN, TRUE, NULL);
    }

    if (gst_structure_has_field_typed(info, "iv", GST_TYPE_BUFFER) &&
        !gst_structure_has_field_typed(info, "iv_size", G_TYPE_UINT))
    {
        const GValue *value = gst_structure_get_value(info, "iv");
        if (value)
        {
            GstBuffer *ivBuffer = gst_value_get_buffer(value);
            // Set iv size
            gst_structure_set(info, "iv_size", G_TYPE_UINT, gst_buffer_get_size(ivBuffer), NULL);
        }
    }

    if (!gst_structure_has_field_typed(info, "encryption_scheme", G_TYPE_UINT))
    {
        // Not used but required
        gst_structure_set(info, "encryption_scheme", G_TYPE_UINT, 0, NULL);
    }

    rialto_mse_add_protection_metadata(buffer, info);

    return true;
}

bool OpenCDMSession::closeSession()
{
    bool result = false;
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        if (mCdmBackend->closeKeySession(mRialtoSessionId))
        {
            TRACE_L2("Successfully closed the session");
            mMessageDispatcherClient.reset();
            mChallengeData.clear();
            mKeyStatuses.clear();
            result = true;
        }
        else
        {
            TRACE_L1("Failed to close the session. Got status %u", static_cast<unsigned int>(status));
        }
    }

    return result;
}

bool OpenCDMSession::removeSession()
{
    bool result = false;
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        if (mCdmBackend->removeKeySession(mRialtoSessionId))
        {
            TRACE_L2("Successfully removed the session");
            result = true;
        }
        else
        {
            TRACE_L1("Failed to remove the session. Got status %u", static_cast<unsigned int>(status));
        }
    }

    return result;
}

bool OpenCDMSession::containsKey(const std::vector<uint8_t> &keyId)
{
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        return mCdmBackend->containsKey(mRialtoSessionId, keyId);
    }
    return false;
}

bool OpenCDMSession::setDrmHeader(const std::vector<uint8_t> &drmHeader)
{
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        return mCdmBackend->setDrmHeader(mRialtoSessionId, drmHeader);
    }
    return false;
}

bool OpenCDMSession::selectKeyId(const std::vector<uint8_t> &keyId)
{
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return false;
    }

    if (-1 != mRialtoSessionId)
    {
        return mCdmBackend->selectKeyId(mRialtoSessionId, keyId);
    }

    return false;
}

void OpenCDMSession::onLicenseRequest(int32_t keySessionId, const std::vector<unsigned char> &licenseRequestMessage,
                                      const std::string &url)
{
    if (keySessionId == mRialtoSessionId)
    {
        updateChallenge(licenseRequestMessage);

        if ((mCallbacks) && (mCallbacks->process_challenge_callback))
        {
            mCallbacks->process_challenge_callback(this, mContext, url.c_str(), licenseRequestMessage.data(),
                                                   licenseRequestMessage.size());
        }
    }
}

void OpenCDMSession::onLicenseRenewal(int32_t keySessionId, const std::vector<unsigned char> &licenseRenewalMessage)
{
    if (keySessionId == mRialtoSessionId)
    {
        updateChallenge(licenseRenewalMessage);

        if ((mCallbacks) && (mCallbacks->process_challenge_callback))
        {
            mCallbacks->process_challenge_callback(this, mContext, "" /*URL*/, licenseRenewalMessage.data(),
                                                   licenseRenewalMessage.size());
        }
    }
}

void OpenCDMSession::updateChallenge(const std::vector<unsigned char> &challenge)
{
    std::unique_lock<std::mutex> lock{mMutex};
    mChallengeData = challenge;
    mChallengeCv.notify_one();
}

void OpenCDMSession::onKeyStatusesChanged(int32_t keySessionId, const firebolt::rialto::KeyStatusVector &keyStatuses)
{
    if ((keySessionId == mRialtoSessionId) && (mCallbacks) && (mCallbacks->key_update_callback))
    {
        for (const std::pair<std::vector<uint8_t>, firebolt::rialto::KeyStatus> &keyStatus : keyStatuses)
        {
            // Update internal key statuses
            mKeyStatuses[keyStatus.first] = keyStatus.second;

            const std::vector<uint8_t> &key = keyStatus.first;
            mCallbacks->key_update_callback(this, mContext, key.data(), key.size());
        }

        if (mCallbacks->keys_updated_callback)
        {
            mCallbacks->keys_updated_callback(this, mContext);
        }
    }
}

KeyStatus OpenCDMSession::status(const std::vector<uint8_t> &key) const
{
    auto it = mKeyStatuses.find(key);
    if (it != mKeyStatuses.end())
    {
        return convertKeyStatus(it->second);
    }
    return KeyStatus::InternalError;
}

const std::string &OpenCDMSession::getSessionId() const
{
    return mCdmKeySessionId;
}

void OpenCDMSession::initializeCdmKeySessionId()
{
    bool result{false};
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return;
    }

    if (-1 != mRialtoSessionId)
    {
        result = mCdmBackend->getCdmKeySessionId(mRialtoSessionId, mCdmKeySessionId);
    }
    if (!result)
    {
        mCdmKeySessionId = kDefaultSessionId;
    }
}

uint32_t OpenCDMSession::getLastDrmError() const
{
    uint32_t err = 0;
    if (!mCdmBackend)
    {
        TRACE_L1("Cdm is NULL or not initialized");
        return -1;
    }

    (void)mCdmBackend->getLastDrmError(mRialtoSessionId, err);

    return err;
}

firebolt::rialto::KeySessionType OpenCDMSession::getRialtoSessionType(const LicenseType licenseType)
{
    switch (licenseType)
    {
    case Temporary:
        return firebolt::rialto::KeySessionType::TEMPORARY;
    case PersistentUsageRecord: /// TODO: Rialto's equivalent??
        return firebolt::rialto::KeySessionType::UNKNOWN;
    case PersistentLicense:
        return firebolt::rialto::KeySessionType::PERSISTENT_LICENCE;
    default:
        return firebolt::rialto::KeySessionType::UNKNOWN;
    }
}

firebolt::rialto::InitDataType OpenCDMSession::getRialtoInitDataType(const std::string &type)
{
    firebolt::rialto::InitDataType initDataType = firebolt::rialto::InitDataType::UNKNOWN;

    if (type == "cenc")
    {
        initDataType = firebolt::rialto::InitDataType::CENC;
    }
    else if (type == "webm")
    {
        initDataType = firebolt::rialto::InitDataType::WEBM;
    }
    else if (type == "drmheader")
    {
        initDataType = firebolt::rialto::InitDataType::DRMHEADER;
    }

    return initDataType;
}
