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

#ifndef OPENCDM_SESSION_MOCK_H_
#define OPENCDM_SESSION_MOCK_H_

#include "OpenCDMSession.h"
#include <gmock/gmock.h>
#include <string>
#include <vector>

class OpenCDMSessionMock : public OpenCDMSession
{
public:
    MOCK_METHOD(bool, initialize, (), (override));
    MOCK_METHOD(bool, generateRequest,
                (const std::string &initDataType, const std::vector<uint8_t> &initData,
                 const std::vector<uint8_t> &cdmData),
                (override));
    MOCK_METHOD(bool, loadSession, (), (override));
    MOCK_METHOD(bool, updateSession, (const std::vector<uint8_t> &license), (override));
    MOCK_METHOD(bool, getChallengeData, (std::vector<uint8_t> & challengeData, bool isLdl), (override));
    MOCK_METHOD(bool, getChallengeDataSize, (uint32_t & size, bool isLdl), (override));
    MOCK_METHOD(bool, containsKey, (const std::vector<uint8_t> &keyId), (override));
    MOCK_METHOD(bool, setDrmHeader, (const std::vector<uint8_t> &drmHeader), (override));
    MOCK_METHOD(bool, selectKeyId, (const std::vector<uint8_t> &keyId), (override));
    MOCK_METHOD(void, addProtectionMeta,
                (GstBuffer * buffer, GstBuffer *subSample, const uint32_t subSampleCount, GstBuffer *IV,
                 GstBuffer *keyID, uint32_t initWithLast15),
                (override));
    MOCK_METHOD(bool, addProtectionMeta, (GstBuffer * buffer), (override));
    MOCK_METHOD(bool, closeSession, (), (override));
    MOCK_METHOD(bool, removeSession, (), (override));
    MOCK_METHOD(KeyStatus, status, (const std::vector<uint8_t> &key), (const, override));
    MOCK_METHOD(const std::string &, getSessionId, (), (const, override));
    MOCK_METHOD(uint32_t, getLastDrmError, (), (const, override));
};

#endif // OPENCDM_SESSION_MOCK_H_
