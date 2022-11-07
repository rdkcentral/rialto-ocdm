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

#ifndef CDMBACKEND_H
#define CDMBACKEND_H

#include "MediaKeysClient.h"
#include <IMediaKeys.h>
#include <IMediaKeysCapabilities.h>

class CdmBackend
{
public:
    CdmBackend() {}
    ~CdmBackend() {}

    static const std::shared_ptr<firebolt::rialto::IMediaKeysCapabilities> &getMediaKeysCapabilities();
    const std::unique_ptr<firebolt::rialto::IMediaKeys> &getMediaKeys() const;
    std::shared_ptr<MediaKeysClient> getMediaKeysClient();

    bool createMediaKeys(const std::string &keySystem);
    void destroyMediaKeys();

private:
    static std::shared_ptr<firebolt::rialto::IMediaKeysCapabilities> m_mediaKeysCapabilities;
    std::unique_ptr<firebolt::rialto::IMediaKeys> m_mediaKeys;
    std::shared_ptr<MediaKeysClient> m_mediaKeysClient;
};

#endif // CDMBACKEND_H
