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

#ifndef CDM_BACKEND_MOCK_H_
#define CDM_BACKEND_MOCK_H_

#include "ICdmBackend.h"
#include <gmock/gmock.h>
#include <string>
#include <vector>

class CdmBackendMock : public ICdmBackend
{
public:
    MOCK_METHOD(bool, initialize, (const firebolt::rialto::ApplicationState &initialState), (override));
    MOCK_METHOD(bool, selectKeyId, (int32_t keySessionId, const std::vector<uint8_t> &keyId), (override));
    MOCK_METHOD(bool, containsKey, (int32_t keySessionId, const std::vector<uint8_t> &keyId), (override));
    MOCK_METHOD(bool, createKeySession, (firebolt::rialto::KeySessionType sessionType, int32_t &keySessionId),
                (override));
    MOCK_METHOD(bool, generateRequest,
                (int32_t keySessionId, firebolt::rialto::InitDataType initDataType,
                 const std::vector<uint8_t> &initData, const firebolt::rialto::LimitedDurationLicense &ldlState),
                (override));
    MOCK_METHOD(bool, loadSession, (int32_t keySessionId), (override));
    MOCK_METHOD(bool, updateSession, (int32_t keySessionId, const std::vector<uint8_t> &responseData), (override));
    MOCK_METHOD(bool, setDrmHeader, (int32_t keySessionId, const std::vector<uint8_t> &requestData), (override));
    MOCK_METHOD(bool, closeKeySession, (int32_t keySessionId), (override));
    MOCK_METHOD(bool, removeKeySession, (int32_t keySessionId), (override));
    MOCK_METHOD(bool, deleteDrmStore, (), (override));
    MOCK_METHOD(bool, deleteKeyStore, (), (override));
    MOCK_METHOD(bool, getDrmStoreHash, (std::vector<unsigned char> & drmStoreHash), (override));
    MOCK_METHOD(bool, getKeyStoreHash, (std::vector<unsigned char> & keyStoreHash), (override));
    MOCK_METHOD(bool, getLdlSessionsLimit, (uint32_t & ldlLimit), (override));
    MOCK_METHOD(bool, getLastDrmError, (int32_t keySessionId, uint32_t &errorCode), (override));
    MOCK_METHOD(bool, getDrmTime, (uint64_t & drmTime), (override));
    MOCK_METHOD(bool, getCdmKeySessionId, (int32_t keySessionId, std::string &cdmKeySessionId), (override));
    MOCK_METHOD(bool, releaseKeySession, (int32_t keySessionId), (override));
    MOCK_METHOD(bool, getMetricSystemData, (std::vector<uint8_t> & buffer), (override));
};

#endif // CDM_BACKEND_MOCK_H_
