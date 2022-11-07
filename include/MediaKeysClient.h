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

#ifndef MEDIA_KEYS_CLIENT_H_
#define MEDIA_KEYS_CLIENT_H_

#include "IMediaKeysClient.h"
#include <map>
#include <mutex>
#include <string>
#include <vector>

class MediaKeysClient : public firebolt::rialto::IMediaKeysClient
{
public:
    MediaKeysClient() = default;
    ~MediaKeysClient() override = default;

    void addHandler(int32_t keySessionId, firebolt::rialto::IMediaKeysClient *handler);
    void removeHandler(int32_t keySessionId);

    void onLicenseRequest(int32_t keySessionId, const std::vector<unsigned char> &licenseRequestMessage,
                          const std::string &url) override;
    void onLicenseRenewal(int32_t keySessionId, const std::vector<unsigned char> &licenseRenewalMessage) override;
    void onKeyStatusesChanged(int32_t keySessionId, const firebolt::rialto::KeyStatusVector &keyStatuses) override;

private:
    std::mutex m_mutex;
    std::map<int32_t, firebolt::rialto::IMediaKeysClient *> m_handlers;
};

#endif // MEDIA_KEYS_CLIENT_H_
