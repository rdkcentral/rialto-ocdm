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

#include <opencdm/open_cdm.h>

#include "ActiveSessions.h"
#include <OpenCDMSession.h>
#include <OpenCDMSystem.h>
#include <Utils.h>
#include <WPEFramework/core/Trace.h>

OpenCDMSystem *opencdm_create_system(const char keySystem[])
{
    OpenCDMSystem *result = nullptr;
    opencdm_create_system_extended(keySystem, &result);

    return result;
}

OpenCDMError opencdm_create_system_extended(const char keySystem[], struct OpenCDMSystem **system)
{
    assert(system != nullptr);

    std::shared_ptr<CdmBackend> backend = std::make_shared<CdmBackend>();
    if (!backend)
    {
        return ERROR_FAIL;
    }

    if (!backend->createMediaKeys(keySystem))
    {
        return ERROR_FAIL;
    }

    *system = new OpenCDMSystem(keySystem, "", backend);

    return ERROR_NONE;
}

OpenCDMError opencdm_destruct_system(struct OpenCDMSystem *system)
{
    if (system)
    {
        delete system;
    }

    return ERROR_NONE;
}

OpenCDMError opencdm_is_type_supported(const char keySystem[], const char mimeType[])
{
    if (!CdmBackend::getMediaKeysCapabilities()->supportsKeySystem(std::string(keySystem)))
    {
        return ERROR_KEYSYSTEM_NOT_SUPPORTED;
    }

    /// TODO: check mime
    return ERROR_NONE;
}

OpenCDMError opencdm_system_get_metadata(struct OpenCDMSystem *system, char metadata[], uint16_t *metadataSize)
{
    *metadataSize = 0;
    return ERROR_NONE;
}

OpenCDMError opencdm_system_get_version(struct OpenCDMSystem *system, char versionStr[])
{
    std::string version;
    if (!CdmBackend::getMediaKeysCapabilities()->getSupportedKeySystemVersion(system->keySystem(), version))
    {
        return ERROR_FAIL;
    }

    const size_t MAX_LEN = 64;
    snprintf(versionStr, MAX_LEN, "%s", version.c_str());

    return ERROR_NONE;
}

OpenCDMError opencdm_system_get_drm_time(struct OpenCDMSystem *system, uint64_t *time)
{
    if ((system->getCdmBackend()->getMediaKeys()->getDrmTime(*time) != firebolt::rialto::MediaKeyErrorStatus::OK))
    {
        TRACE_L1("Failed to get DRM Time");
        return ERROR_FAIL;
    }
    return ERROR_NONE;
}

struct OpenCDMSession *opencdm_get_system_session(struct OpenCDMSystem *system, const uint8_t keyId[],
                                                  const uint8_t length, const uint32_t waitTime)
{
    return ActiveSessions::instance().get(std::vector<uint8_t>(keyId, keyId + length));
}

OpenCDMError opencdm_system_set_server_certificate(struct OpenCDMSystem *system, const uint8_t serverCertificate[],
                                                   const uint16_t serverCertificateLength)
{
    return ERROR_NONE;
}

struct OpenCDMSession *opencdm_get_session(const uint8_t keyId[], const uint8_t length, const uint32_t waitTime)
{
    return opencdm_get_system_session(nullptr, keyId, length, waitTime);
}

OpenCDMError opencdm_construct_session(struct OpenCDMSystem *system, const LicenseType licenseType,
                                       const char initDataType[], const uint8_t initData[],
                                       const uint16_t initDataLength, const uint8_t CDMData[],
                                       const uint16_t CDMDataLength, OpenCDMSessionCallbacks *callbacks, void *userData,
                                       struct OpenCDMSession **session)
{
    OpenCDMSession *newSession = nullptr;

    std::string initializationDataType(initDataType);
    std::vector<uint8_t> initDataVec((uint8_t *)(initData), (uint8_t *)(initData) + initDataLength);

    newSession = ActiveSessions::instance().create(system->getCdmBackend(), system->keySystem(), licenseType, callbacks,
                                                   userData, initializationDataType, initDataVec);

    if (!newSession)
    {
        return ERROR_INVALID_SESSION;
    }

    if (!isNetflixKeysystem(system->keySystem()))
    {
        if (!newSession->initialize())
        {
            TRACE_L1("Failed to create session");
            ActiveSessions::instance().remove(newSession);
            return ERROR_FAIL;
        }
        std::vector<uint8_t> cdmDataVec((uint8_t *)(CDMData), (uint8_t *)(CDMData) + CDMDataLength);
        std::vector<uint8_t> challenge;

        if (!newSession->generateRequest(initializationDataType, initDataVec, cdmDataVec /*not used yet*/))
        {
            TRACE_L1("Failed to generate request");

            opencdm_session_close(newSession);
            ActiveSessions::instance().remove(newSession);
            return ERROR_FAIL;
        }
    }

    *session = newSession;

    return ERROR_NONE;
}

OpenCDMError opencdm_destruct_session(struct OpenCDMSession *session)
{
    // MKS is destructed in opencdm_session_close or in opencdm_session_clean_decrypt_context
    ActiveSessions::instance().remove(session);
    return ERROR_NONE;
}

OpenCDMError opencdm_session_load(struct OpenCDMSession *session)
{
    OpenCDMError result = ERROR_INVALID_SESSION;
    if (session)
    {
        if (session->loadSession())
        {
            result = ERROR_NONE;
        }
        else
        {
            TRACE_L1("Failed to load the session");
            result = ERROR_FAIL;
        }
    }

    return result;
}

OpenCDMError opencdm_session_metadata(const struct OpenCDMSession *session, char metadata[], uint16_t *metadataSize)
{
    return ERROR_NONE;
}

const char *opencdm_session_id(const struct OpenCDMSession *session)
{
    return session->getSessionId().c_str();
}

const char *opencdm_session_buffer_id(const struct OpenCDMSession *session)
{
    return nullptr;
}

uint32_t opencdm_session_has_key_id(struct OpenCDMSession *session, const uint8_t length, const uint8_t keyId[])
{
    if (!session)
    {
        TRACE_L1("Failed to check key id");
        return 0;
    }
    std::vector<uint8_t> key(keyId, keyId + length);
    return static_cast<uint32_t>(session->containsKey(key));
}

KeyStatus opencdm_session_status(const struct OpenCDMSession *session, const uint8_t keyId[], uint8_t length)
{
    if (session)
    {
        std::vector<uint8_t> key(keyId, keyId + length);
        return session->status(key);
    }

    return InternalError;
}

uint32_t opencdm_session_error(const struct OpenCDMSession *session, const uint8_t keyId[], uint8_t length)
{
    TRACE_L1("%s NOT IMPLEMENTED YET", __FUNCTION__);
    return 0;
}

OpenCDMError opencdm_session_system_error(const struct OpenCDMSession *session)
{
    uint32_t err = session->getLastDrmError();
    // Rialto doesn't implement it yet
    switch (err)
    {
    default:
        return ERROR_NONE;
    }
}

OpenCDMError opencdm_session_update(struct OpenCDMSession *session, const uint8_t keyMessage[], uint16_t keyLength)
{
    OpenCDMError result = ERROR_INVALID_SESSION;
    std::vector<uint8_t> license(keyMessage, keyMessage + keyLength);

    if (session)
    {
        if (session->updateSession(license))
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

OpenCDMError opencdm_session_remove(struct OpenCDMSession *session)
{
    OpenCDMError result = ERROR_INVALID_SESSION;
    if (session)
    {
        if (session->removeSession())
        {
            result = ERROR_NONE;
        }
        else
        {
            TRACE_L1("Failed to remove the key session");
            result = ERROR_FAIL;
        }
    }

    return result;
}

OpenCDMError opencdm_session_resetoutputprotection(struct OpenCDMSession *session)
{
    TRACE_L1("%s NOT IMPLEMENTED YET", __FUNCTION__);
    return ERROR_NONE;
}

OpenCDMError opencdm_session_set_parameter(struct OpenCDMSession *session, const std::string &name,
                                           const std::string &value)
{
    TRACE_L1("%s NOT IMPLEMENTED YET", __FUNCTION__);
    return ERROR_NONE;
}

OpenCDMError opencdm_session_close(struct OpenCDMSession *session)
{
    OpenCDMError result = ERROR_INVALID_SESSION;
    if (session)
    {
        if (session->closeSession())
        {
            result = ERROR_NONE;
        }
        else
        {
            TRACE_L1("Failed to close the key session");
            result = ERROR_FAIL;
        }
    }

    return result;
}
