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

#include "MediaKeysClient.h"

void MediaKeysClient::addHandler(int32_t keySessionId, firebolt::rialto::IMediaKeysClient *handler)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_handlers.emplace(std::make_pair(keySessionId, handler));
}

void MediaKeysClient::removeHandler(int32_t keySessionId)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_handlers.erase(keySessionId);
}

void MediaKeysClient::onLicenseRequest(int32_t keySessionId, const std::vector<unsigned char> &licenseRequestMessage,
                                       const std::string &url)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    auto handler{m_handlers.find(keySessionId)};
    if (handler != m_handlers.end())
    {
        handler->second->onLicenseRequest(keySessionId, licenseRequestMessage, url);
    }
}

void MediaKeysClient::onLicenseRenewal(int32_t keySessionId, const std::vector<unsigned char> &licenseRenewalMessage)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    auto handler{m_handlers.find(keySessionId)};
    if (handler != m_handlers.end())
    {
        handler->second->onLicenseRenewal(keySessionId, licenseRenewalMessage);
    }
}

void MediaKeysClient::onKeyStatusesChanged(int32_t keySessionId, const firebolt::rialto::KeyStatusVector &keyStatuses)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    auto handler{m_handlers.find(keySessionId)};
    if (handler != m_handlers.end())
    {
        handler->second->onKeyStatusesChanged(keySessionId, keyStatuses);
    }
}
