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

#ifndef CDMBACKEND_H
#define CDMBACKEND_H

#include "ICdmBackend.h"
#include "Logger.h"
#include "MessageDispatcher.h"
#include <IControlClient.h>
#include <IMediaKeys.h>
#include <mutex>

class CdmBackend : public ICdmBackend, public firebolt::rialto::IControlClient
{
public:
    CdmBackend(const std::string &keySystem, const std::shared_ptr<MessageDispatcher> &messageDispatcher);
    ~CdmBackend() override = default;

    void notifyApplicationState(firebolt::rialto::ApplicationState state) override;

    bool initialize(const firebolt::rialto::ApplicationState &initialState) override;

    bool selectKeyId(int32_t keySessionId, const std::vector<uint8_t> &keyId) override;
    bool containsKey(int32_t keySessionId, const std::vector<uint8_t> &keyId) override;
    bool createKeySession(firebolt::rialto::KeySessionType sessionType, bool isLDL, int32_t &keySessionId) override;
    bool generateRequest(int32_t keySessionId, firebolt::rialto::InitDataType initDataType,
                         const std::vector<uint8_t> &initData) override;
    bool loadSession(int32_t keySessionId) override;
    bool updateSession(int32_t keySessionId, const std::vector<uint8_t> &responseData) override;
    bool setDrmHeader(int32_t keySessionId, const std::vector<uint8_t> &requestData) override;
    bool closeKeySession(int32_t keySessionId) override;
    bool removeKeySession(int32_t keySessionId) override;
    bool deleteDrmStore() override;
    bool deleteKeyStore() override;
    bool getDrmStoreHash(std::vector<unsigned char> &drmStoreHash) override;
    bool getKeyStoreHash(std::vector<unsigned char> &keyStoreHash) override;
    bool getLdlSessionsLimit(uint32_t &ldlLimit) override;
    bool getLastDrmError(int32_t keySessionId, uint32_t &errorCode) override;
    bool getDrmTime(uint64_t &drmTime) override;
    bool getCdmKeySessionId(int32_t keySessionId, std::string &cdmKeySessionId) override;

private:
    bool createMediaKeys();

private:
    Logger mLog;
    std::mutex mMutex;
    firebolt::rialto::ApplicationState mAppState;
    const std::string mKeySystem;
    std::shared_ptr<MessageDispatcher> mMessageDispatcher;
    std::unique_ptr<firebolt::rialto::IMediaKeys> mMediaKeys;
};

#endif // CDMBACKEND_H
