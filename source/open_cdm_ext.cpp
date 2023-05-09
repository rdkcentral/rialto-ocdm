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

#include <OpenCDMSession.h>
#include <OpenCDMSystem.h>
#include <Utils.h>
#include <WPEFramework/core/Trace.h>
#include <opencdm/open_cdm_ext.h>

OpenCDMError opencdm_system_ext_get_ldl_session_limit(struct OpenCDMSystem *system, uint32_t *ldlLimit)
{
    if (!system || !ldlLimit)
    {
        TRACE_L1("Failed to get ldl session limit - System is NULL");
        return ERROR_FAIL;
    }

    if (!system->getLdlSessionsLimit(*ldlLimit))
    {
        TRACE_L1("Failed to get LDL Session limit");
        return ERROR_FAIL;
    }
    return ERROR_NONE;
}

uint32_t opencdm_system_ext_is_secure_stop_enabled(struct OpenCDMSystem *system)
{
    TRACE_L2("Secure stop not supported");
    return 0;
}

OpenCDMError opencdm_system_ext_enable_secure_stop(struct OpenCDMSystem *system, uint32_t use)
{
    TRACE_L2("Secure stop not supported");
    return ERROR_FAIL;
}

uint32_t opencdm_system_ext_reset_secure_stop(struct OpenCDMSystem *system)
{
    TRACE_L2("Reset secure stop not supported");
    return 0;
}

OpenCDMError opencdm_system_ext_get_secure_stop_ids(struct OpenCDMSystem *system, uint8_t Ids[], uint16_t idsLength,
                                                    uint32_t *count)
{
    TRACE_L1("Failed to get secure stop ids - not supported");
    return ERROR_FAIL;
}

OpenCDMError opencdm_system_ext_get_secure_stop(struct OpenCDMSystem *system, const uint8_t sessionID[],
                                                uint32_t sessionIDLength, uint8_t rawData[], uint16_t *rawSize)
{
    TRACE_L1("Failed to get secure stop - not supported");
    return ERROR_FAIL;
}

OpenCDMError opencdm_system_ext_commit_secure_stop(struct OpenCDMSystem *system, const uint8_t sessionID[],
                                                   uint32_t sessionIDLength, const uint8_t serverResponse[],
                                                   uint32_t serverResponseLength)
{
    TRACE_L1("Failed to commit secure stop - not supported");
    return ERROR_FAIL;
}

OpenCDMError opencdm_get_key_store_hash_ext(struct OpenCDMSystem *system, uint8_t keyStoreHash[],
                                            uint32_t keyStoreHashLength)
{
    if (!system || 0 == keyStoreHashLength)
    {
        TRACE_L1("Failed to get key store hash - arguments are not valid");
        return ERROR_FAIL;
    }
    std::vector<uint8_t> keyStoreHashVec;
    if (!system->getKeyStoreHash(keyStoreHashVec))
    {
        TRACE_L1("Failed to get key store hash - operation failed");
        return ERROR_FAIL;
    }
    if (keyStoreHashVec.size() > keyStoreHashLength)
    {
        TRACE_L1("Failed to get key store hash - return of size %u does not fit in buffer of size %u",
                 keyStoreHashVec.size(), keyStoreHashLength);
        return ERROR_FAIL;
    }
    memcpy(keyStoreHash, keyStoreHashVec.data(), keyStoreHashVec.size());
    return ERROR_NONE;
}

OpenCDMError opencdm_get_secure_store_hash_ext(struct OpenCDMSystem *system, uint8_t secureStoreHash[],
                                               uint32_t secureStoreHashLength)
{
    if (!system || 0 == secureStoreHashLength)
    {
        TRACE_L1("Failed to get secure store hash - arguments are not valid");
        return ERROR_FAIL;
    }
    std::vector<uint8_t> secureStoreHashVec;
    if (!system->getDrmStoreHash(secureStoreHashVec))
    {
        TRACE_L1("Failed to get secure store hash - operation failed");
        return ERROR_FAIL;
    }
    if (secureStoreHashVec.size() > secureStoreHashLength)
    {
        TRACE_L1("Failed to get key store hash - return size %u does not fit in buffer of size %u",
                 secureStoreHashVec.size(), secureStoreHashLength);
        return ERROR_FAIL;
    }
    memcpy(secureStoreHash, secureStoreHashVec.data(), secureStoreHashVec.size());
    return ERROR_NONE;
}

OpenCDMError opencdm_delete_key_store(struct OpenCDMSystem *system)
{
    if (!system)
    {
        TRACE_L1("Failed to delete key store - arguments are not valid");
        return ERROR_FAIL;
    }
    if (!system->deleteKeyStore())
    {
        TRACE_L1("Failed to delete key store - operation failed");
        return ERROR_FAIL;
    }
    return ERROR_NONE;
}

OpenCDMError opencdm_delete_secure_store(struct OpenCDMSystem *system)
{
    if (!system)
    {
        TRACE_L1("Failed to delete secure store - arguments are not valid");
        return ERROR_FAIL;
    }
    if (!system->deleteDrmStore())
    {
        TRACE_L1("Failed to delete secure store - operation failed");
        return ERROR_FAIL;
    }
    return ERROR_NONE;
}

OpenCDMError opencdm_session_set_drm_header(struct OpenCDMSession *opencdmSession, const uint8_t drmHeader[],
                                            uint32_t drmHeaderSize)
{
    if (nullptr == opencdmSession)
    {
        TRACE_L1("Failed to set Drm Header - session is NULL");
        return ERROR_FAIL;
    }
    std::vector<uint8_t> drmHeaderVec(drmHeader, drmHeader + drmHeaderSize);
    if (opencdmSession->setDrmHeader(drmHeaderVec))
    {
        TRACE_L1("Failed to set Drm Header - operation returned NOK status");
        return ERROR_FAIL;
    }
    return ERROR_NONE;
}

OpenCDMError opencdm_session_get_challenge_data(struct OpenCDMSession *mOpenCDMSession, uint8_t *challenge,
                                                uint32_t *challengeSize, uint32_t isLDL)
{
    if (nullptr == mOpenCDMSession || nullptr == challengeSize)
    {
        TRACE_L1("Failed to get challenge data - arguments are not valid");
        return ERROR_FAIL;
    }
    if (!mOpenCDMSession->initialize(isLDL))
    {
        TRACE_L1("Failed to create session");
        return ERROR_FAIL;
    }
    std::vector<uint8_t> challengeVec;
    if (!mOpenCDMSession->getChallengeData(challengeVec))
    {
        TRACE_L1("Failed to get challenge data - operation returned NOK status");
        return ERROR_FAIL;
    }
    *challengeSize = challengeVec.size();
    if (nullptr != challenge)
    {
        memcpy(challenge, challengeVec.data(), challengeVec.size());
    }
    return ERROR_NONE;
}

OpenCDMError opencdm_session_cancel_challenge_data(struct OpenCDMSession *mOpenCDMSession)
{
    // MKS is destructed in opencdm_session_clean_decrypt_context
    return ERROR_NONE;
}

OpenCDMError opencdm_session_store_license_data(struct OpenCDMSession *mOpenCDMSession, const uint8_t licenseData[],
                                                uint32_t licenseDataSize, uint8_t *secureStopId)
{
    OpenCDMError result = ERROR_INVALID_SESSION;
    std::vector<uint8_t> license(licenseData, licenseData + licenseDataSize);

    if (mOpenCDMSession)
    {
        if (mOpenCDMSession->updateSession(license))
        {
            result = ERROR_NONE;
        }
        else
        {
            TRACE_L1("Failed to update the session");
            result = ERROR_FAIL;
        }
    }

    return result;
}

OpenCDMError opencdm_session_select_key_id(struct OpenCDMSession *mOpenCDMSession, uint8_t keyLength,
                                           const uint8_t keyId[])
{
    if (!mOpenCDMSession)
    {
        TRACE_L1("Failed to select key id - session is NULL");
        return ERROR_FAIL;
    }
    std::vector<uint8_t> keyIdVec(keyId, keyId + keyLength);
    if (!mOpenCDMSession->selectKeyId(keyIdVec))
    {
        TRACE_L1("Failed to select key id - operation returned NOK status");
        return ERROR_FAIL;
    }
    return ERROR_NONE;
}

OpenCDMError opencdm_system_teardown(struct OpenCDMSystem *system)
{
    return ERROR_NONE;
}

OpenCDMError opencdm_session_clean_decrypt_context(struct OpenCDMSession *mOpenCDMSession)
{
    if (!mOpenCDMSession)
    {
        TRACE_L1("Failed to clean decrypt context - arguments are not valid");
        return ERROR_FAIL;
    }
    if (!mOpenCDMSession->closeSession())
    {
        TRACE_L1("Failed to close the session");
    }
    return ERROR_NONE;
}
