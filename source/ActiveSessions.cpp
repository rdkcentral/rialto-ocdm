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
#include <algorithm>

ActiveSessions &ActiveSessions::instance()
{
    static ActiveSessions activeSessions;
    return activeSessions;
}

OpenCDMSession *ActiveSessions::create(const std::shared_ptr<ICdmBackend> &cdm,
                                       const std::shared_ptr<IMessageDispatcher> &messageDispatcher,
                                       const std::string &keySystem, const LicenseType &sessionType,
                                       OpenCDMSessionCallbacks *callbacks, void *context,
                                       const std::string &initDataType, const std::vector<uint8_t> &initData)
{
    std::unique_lock<std::mutex> lock{mMutex};
    OpenCDMSession *newSession =
        new OpenCDMSession(cdm, messageDispatcher, keySystem, sessionType, callbacks, context, initDataType, initData);
    mActiveSessions.insert(std::make_pair(newSession, 1));
    return newSession;
}

OpenCDMSession *ActiveSessions::get(const std::vector<uint8_t> &keyId)
{
    std::unique_lock<std::mutex> lock{mMutex};
    auto sessionIter{std::find_if(mActiveSessions.begin(), mActiveSessions.end(),
                                  [&](const auto &iter)
                                  { return iter.first->status(keyId) != KeyStatus::InternalError; })};
    if (sessionIter != mActiveSessions.end())
    {
        ++sessionIter->second;
        return sessionIter->first;
    }
    return nullptr;
}

void ActiveSessions::remove(OpenCDMSession *session)
{
    std::unique_lock<std::mutex> lock{mMutex};
    auto sessionIter{mActiveSessions.find(session)};
    if (sessionIter != mActiveSessions.end())
    {
        --sessionIter->second;
        if (0 == sessionIter->second)
        {
            delete sessionIter->first;
            mActiveSessions.erase(sessionIter);
        }
    }
}
