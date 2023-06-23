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

#ifndef OPENCDMSESSION_H
#define OPENCDMSESSION_H

#include "IMediaKeysClient.h"
#include "Logger.h"
#include <ICdmBackend.h>
#include <IMessageDispatcher.h>
#include <MediaCommon.h>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <opencdm/open_cdm.h>
#include <vector>

struct _GstCaps;
struct _GstBuffer;
typedef struct _GstCaps GstCaps;
typedef struct _GstBuffer GstBuffer;

class OpenCDMSession : public firebolt::rialto::IMediaKeysClient
{
public:
    typedef std::function<void(const std::vector<uint8_t> &license_renewal_message, uint64_t session_id)> LicenseRenewalCallback;
    typedef std::function<void(const std::vector<std::pair<std::vector<uint8_t>, firebolt::rialto::KeyStatus>> &key_statuses,
                               uint64_t session_id)>
        KeyStatusesChangedCallback;

    OpenCDMSession(const std::shared_ptr<ICdmBackend> &cdm, const std::shared_ptr<IMessageDispatcher> &messageDispatcher,
                   const LicenseType &sessionType, OpenCDMSessionCallbacks *callbacks, void *context,
                   const std::string &initDataType, const std::vector<uint8_t> &initData);
    ~OpenCDMSession();

    void onLicenseRequest(int32_t keySessionId, const std::vector<unsigned char> &licenseRequestMessage,
                          const std::string &url) override;
    void onLicenseRenewal(int32_t keySessionId, const std::vector<unsigned char> &licenseRenewalMessage) override;
    void onKeyStatusesChanged(int32_t keySessionId, const firebolt::rialto::KeyStatusVector &keyStatuses) override;

    bool initialize();
    bool initialize(bool);
    bool generateRequest(const std::string &initDataType, const std::vector<uint8_t> &initData,
                         const std::vector<uint8_t> &cdmData);
    bool loadSession();
    bool updateSession(const std::vector<uint8_t> &license);
    bool getChallengeData(std::vector<uint8_t> &challengeData);
    bool containsKey(const std::vector<uint8_t> &keyId);
    bool setDrmHeader(const std::vector<uint8_t> &drmHeader);
    bool selectKeyId(const std::vector<uint8_t> &keyId);
    void addProtectionMeta(GstBuffer *buffer, GstBuffer *subSample, const uint32_t subSampleCount, GstBuffer *IV,
                           GstBuffer *keyID, uint32_t initWithLast15);
    bool addProtectionMeta(GstBuffer *buffer);
    bool closeSession();
    bool removeSession();
    KeyStatus status(const std::vector<uint8_t> &key) const;

    const std::string &getSessionId() const;
    uint32_t getLastDrmError() const;

private:
    void initializeCdmKeySessionId();
    void updateChallenge(const std::vector<unsigned char> &challenge);

private:
    Logger m_log;
    std::mutex m_mutex;
    std::condition_variable m_challengeCv;
    void *m_context;
    std::shared_ptr<ICdmBackend> m_cdmBackend;
    std::shared_ptr<IMessageDispatcher> m_messageDispatcher;
    std::unique_ptr<IMessageDispatcherClient> m_messageDispatcherClient;
    int32_t m_rialtoSessionId;
    std::string m_cdmKeySessionId;
    OpenCDMSessionCallbacks *m_callbacks;
    firebolt::rialto::KeySessionType m_sessionType;
    firebolt::rialto::InitDataType m_initDataType;
    std::vector<uint8_t> m_initData;
    bool m_isInitialized;
    std::vector<uint8_t> m_challengeData;
    std::map<std::vector<unsigned char>, firebolt::rialto::KeyStatus> m_keyStatuses;

    firebolt::rialto::KeySessionType getRialtoSessionType(const LicenseType licenseType);
    firebolt::rialto::InitDataType getRialtoInitDataType(const std::string &type);
};

#endif // OPENCDMSESSION_H
