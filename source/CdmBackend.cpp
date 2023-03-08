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

#include "CdmBackend.h"

std::shared_ptr<firebolt::rialto::IMediaKeysCapabilities> CdmBackend::m_mediaKeysCapabilities;

const std::shared_ptr<firebolt::rialto::IMediaKeysCapabilities> CdmBackend::getMediaKeysCapabilities()
{
    if (!m_mediaKeysCapabilities)
    {
        std::shared_ptr<firebolt::rialto::IMediaKeysCapabilitiesFactory> factory =
            firebolt::rialto::IMediaKeysCapabilitiesFactory::createFactory();
        if (!factory)
        {
            return nullptr;
        }

        m_mediaKeysCapabilities = factory->getMediaKeysCapabilities();
    }

    return m_mediaKeysCapabilities;
}

const std::unique_ptr<firebolt::rialto::IMediaKeys> &CdmBackend::getMediaKeys() const
{
    return m_mediaKeys;
}

std::shared_ptr<MediaKeysClient> CdmBackend::getMediaKeysClient()
{
    return m_mediaKeysClient;
}

bool CdmBackend::createMediaKeys(const std::string &keySystem)
{
    std::shared_ptr<firebolt::rialto::IMediaKeysFactory> factory = firebolt::rialto::IMediaKeysFactory::createFactory();
    if (!factory)
    {
        return false;
    }

    m_mediaKeys = factory->createMediaKeys(keySystem);
    if (!m_mediaKeys)
    {
        return false;
    }
    m_mediaKeysClient = std::make_shared<MediaKeysClient>();
    if (!m_mediaKeysClient)
    {
        return false;
    }

    return true;
}

void CdmBackend::destroyMediaKeys()
{
    m_mediaKeys.reset();
}
