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

#ifndef OPENCDM_SYSTEM_MOCK_H_
#define OPENCDM_SYSTEM_MOCK_H_

#include "OpenCDMSystem.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>

class OpenCDMSystemMock : public OpenCDMSystem
{
public:
    MOCK_METHOD(const std::string &, keySystem, (), (const, override));
    MOCK_METHOD(const std::string &, metadata, (), (const, override));
    MOCK_METHOD(OpenCDMSession *, createSession,
                (const LicenseType licenseType, OpenCDMSessionCallbacks *callbacks, void *userData,
                 const std::string &initDataType, const std::vector<uint8_t> &initData),
                (const, override));
    MOCK_METHOD(bool, getDrmTime, (uint64_t & drmTime), (const, override));
    MOCK_METHOD(bool, getLdlSessionsLimit, (uint32_t & ldlLimit), (const, override));
    MOCK_METHOD(bool, getKeyStoreHash, (std::vector<unsigned char> & keyStoreHash), (const, override));
    MOCK_METHOD(bool, getDrmStoreHash, (std::vector<unsigned char> & drmStoreHash), (const, override));
    MOCK_METHOD(bool, deleteKeyStore, (), (const, override));
    MOCK_METHOD(bool, deleteDrmStore, (), (const, override));
    MOCK_METHOD(bool, getMetricSystemData, (uint32_t * bufferLength, uint8_t *buffer), (const, override));
};

#endif // OPENCDM_SYSTEM_MOCK_H_
