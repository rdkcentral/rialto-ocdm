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
#include "OpenCDMSessionPrivate.h"
#include <algorithm>
#include <chrono>

ActiveSessions &ActiveSessions::instance()
{
    static ActiveSessions activeSessions;
    return activeSessions;
}

OpenCDMSession *ActiveSessions::create(const OpenCDMSystem *system, const std::shared_ptr<ICdmBackend> &cdm,
                                       const std::shared_ptr<IMessageDispatcher> &messageDispatcher,
                                       const LicenseType &sessionType, OpenCDMSessionCallbacks *callbacks,
                                       void *context, const std::string &initDataType,
                                       const std::vector<uint8_t> &initData)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    OpenCDMSession *newSession =
        new OpenCDMSessionPrivate(cdm, messageDispatcher, sessionType, callbacks, context, initDataType, initData);
    m_activeSessions.insert(std::make_pair(newSession, SessionEntry{1, system}));
    m_cv.notify_all();
    return newSession;
}

OpenCDMSession *ActiveSessions::get(const std::vector<uint8_t> &keyId, const OpenCDMSystem *system,
                                    uint32_t waitTimeMs)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{waitTimeMs};
    std::unique_lock<std::mutex> lock{m_mutex};
    for (;;)
    {
        auto sessionIter{std::find_if(m_activeSessions.begin(), m_activeSessions.end(), [&](const auto &iter)
                                      { return (nullptr == system || iter.second.system == system) &&
                                               iter.first->status(keyId) != KeyStatus::InternalError; })};
        if (sessionIter != m_activeSessions.end())
        {
            ++sessionIter->second.refCount;
            return sessionIter->first;
        }
        if (std::chrono::steady_clock::now() >= deadline)
        {
            return nullptr;
        }
        // Re-check at least every 50ms so late key-status updates are also picked up.
        m_cv.wait_for(lock, std::chrono::milliseconds{50});
    }
}

void ActiveSessions::remove(OpenCDMSession *session)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    auto sessionIter{m_activeSessions.find(session)};
    if (sessionIter != m_activeSessions.end())
    {
        --sessionIter->second.refCount;
        if (0 == sessionIter->second.refCount)
        {
            delete sessionIter->first;
            m_activeSessions.erase(sessionIter);
        }
    }
}
