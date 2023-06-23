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

#include "ActiveSessions.h"
#include "CdmBackend.h"
#include "MessageDispatcher.h"
#include <IControl.h>
#include <memory>
#include <string>

struct OpenCDMSystem
{
    OpenCDMSystem(const char system[], const std::string &metadata);
    ~OpenCDMSystem() = default;
    OpenCDMSystem(const OpenCDMSystem &) = default;
    OpenCDMSystem(OpenCDMSystem &&) = default;
    OpenCDMSystem &operator=(OpenCDMSystem &&) = default;
    OpenCDMSystem &operator=(const OpenCDMSystem &) = default;
    const std::string &keySystem() const;
    const std::string &Metadata() const;
    OpenCDMSession *createSession(const LicenseType licenseType, OpenCDMSessionCallbacks *callbacks, void *userData,
                                  const std::string &initDataType, const std::vector<uint8_t> &initData) const;
    bool getDrmTime(uint64_t &drmTime) const;
    bool getLdlSessionsLimit(uint32_t &ldlLimit) const;
    bool getKeyStoreHash(std::vector<unsigned char> &keyStoreHash) const;
    bool getDrmStoreHash(std::vector<unsigned char> &drmStoreHash) const;
    bool deleteKeyStore() const;
    bool deleteDrmStore() const;

private:
    std::string m_keySystem;
    std::string m_metadata;
    std::shared_ptr<firebolt::rialto::IControl> m_control;
    std::shared_ptr<MessageDispatcher> m_messageDispatcher;
    std::shared_ptr<CdmBackend> m_cdmBackend;
};
