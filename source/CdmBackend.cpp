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
#include <WPEFramework/core/Trace.h>

CdmBackend::CdmBackend(const std::string &keySystem, const std::shared_ptr<MessageDispatcher> &messageDispatcher)
    : mAppState{firebolt::rialto::ApplicationState::UNKNOWN}, mKeySystem{keySystem}, mMessageDispatcher{messageDispatcher}
{
}

void CdmBackend::notifyApplicationState(firebolt::rialto::ApplicationState state)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (state == mAppState)
    {
        return;
    }
    if (firebolt::rialto::ApplicationState::RUNNING == state)
    {
        TRACE_L1("Rialto state changed to: RUNNING");
        if (createMediaKeys())
        {
            mAppState = state;
        }
    }
    else
    {
        TRACE_L1("Rialto state changed to: INACTIVE");
        mMediaKeys.reset();
        mAppState = state;
    }
}

bool CdmBackend::initialize(const firebolt::rialto::ApplicationState &initialState)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (firebolt::rialto::ApplicationState::UNKNOWN != mAppState)
    {
        // CdmBackend initialized by Rialto Client thread in notifyApplicationState()
        return true;
    }
    if (firebolt::rialto::ApplicationState::RUNNING == initialState)
    {
        if (!createMediaKeys())
        {
            return false;
        }
    }
    TRACE_L1("CdmBackend initialized in %s state",
             (firebolt::rialto::ApplicationState::RUNNING == initialState ? "RUNNING" : "INACTIVE"));
    mAppState = initialState;
    return true;
}

bool CdmBackend::selectKeyId(int32_t keySessionId, const std::vector<uint8_t> &keyId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->selectKeyId(keySessionId, keyId);
}

bool CdmBackend::containsKey(int32_t keySessionId, const std::vector<uint8_t> &keyId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return mMediaKeys->containsKey(keySessionId, keyId);
}

bool CdmBackend::createKeySession(firebolt::rialto::KeySessionType sessionType, bool isLDL, int32_t &keySessionId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK ==
           mMediaKeys->createKeySession(sessionType, mMessageDispatcher, isLDL, keySessionId);
}

bool CdmBackend::generateRequest(int32_t keySessionId, firebolt::rialto::InitDataType initDataType,
                                 const std::vector<uint8_t> &initData)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->generateRequest(keySessionId, initDataType, initData);
}

bool CdmBackend::loadSession(int32_t keySessionId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->loadSession(keySessionId);
}

bool CdmBackend::updateSession(int32_t keySessionId, const std::vector<uint8_t> &responseData)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->updateSession(keySessionId, responseData);
}

bool CdmBackend::setDrmHeader(int32_t keySessionId, const std::vector<uint8_t> &requestData)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->setDrmHeader(keySessionId, requestData);
}

bool CdmBackend::closeKeySession(int32_t keySessionId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->closeKeySession(keySessionId);
}

bool CdmBackend::removeKeySession(int32_t keySessionId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->removeKeySession(keySessionId);
}

bool CdmBackend::deleteDrmStore()
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->deleteDrmStore();
}

bool CdmBackend::deleteKeyStore()
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->deleteKeyStore();
}

bool CdmBackend::getDrmStoreHash(std::vector<unsigned char> &drmStoreHash)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->getDrmStoreHash(drmStoreHash);
}

bool CdmBackend::getKeyStoreHash(std::vector<unsigned char> &keyStoreHash)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->getKeyStoreHash(keyStoreHash);
}

bool CdmBackend::getLdlSessionsLimit(uint32_t &ldlLimit)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->getLdlSessionsLimit(ldlLimit);
}

bool CdmBackend::getLastDrmError(int32_t keySessionId, uint32_t &errorCode)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->getLastDrmError(keySessionId, errorCode);
}

bool CdmBackend::getDrmTime(uint64_t &drmTime)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->getDrmTime(drmTime);
}

bool CdmBackend::getCdmKeySessionId(int32_t keySessionId, std::string &cdmKeySessionId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    if (!mMediaKeys)
    {
        return false;
    }
    return firebolt::rialto::MediaKeyErrorStatus::OK == mMediaKeys->getCdmKeySessionId(keySessionId, cdmKeySessionId);
}

bool CdmBackend::createMediaKeys()
{
    std::shared_ptr<firebolt::rialto::IMediaKeysFactory> factory = firebolt::rialto::IMediaKeysFactory::createFactory();
    if (!factory)
    {
        TRACE_L1("Failed to initialize media keys - not possible to create factory");
        return false;
    }

    mMediaKeys = factory->createMediaKeys(mKeySystem);
    if (!mMediaKeys)
    {
        TRACE_L1("Failed to initialize media keys - not possible to create media keys");
        return false;
    }
    return true;
}
