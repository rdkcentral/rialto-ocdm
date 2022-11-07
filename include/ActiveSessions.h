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

#ifndef ACTIVESESSIONS_H
#define ACTIVESESSIONS_H

#include "OpenCDMSession.h"
#include <map>
#include <mutex>

class ActiveSessions
{
public:
    static ActiveSessions &instance();

    OpenCDMSession *create(std::weak_ptr<CdmBackend> cdm, const std::string &keySystem,
                           const LicenseType &sessionType, OpenCDMSessionCallbacks *callbacks, void *context,
                           const std::string &initDataType, const std::vector<uint8_t> &initData);
    OpenCDMSession *get(const std::vector<uint8_t> &keyId);
    void remove(OpenCDMSession *session);

private:
    ActiveSessions() = default;
    ~ActiveSessions() = default;

private:
    std::mutex mMutex;
    std::map<OpenCDMSession *, int> mActiveSessions;
};

#endif // ACTIVESESSIONS_H
