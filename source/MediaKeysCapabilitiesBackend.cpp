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

#include "MediaKeysCapabilitiesBackend.h"

MediaKeysCapabilitiesBackend &MediaKeysCapabilitiesBackend::instance()
{
    static MediaKeysCapabilitiesBackend mkcBackend;
    return mkcBackend;
}

std::vector<std::string> MediaKeysCapabilitiesBackend::getSupportedKeySystems()
{
    if (!m_mediaKeysCapabilities)
    {
        return {};
    }
    return m_mediaKeysCapabilities->getSupportedKeySystems();
}

OpenCDMError MediaKeysCapabilitiesBackend::supportsKeySystem(const std::string &keySystem)
{
    if (!m_mediaKeysCapabilities)
    {
        return ERROR_FAIL;
    }
    if (!m_mediaKeysCapabilities->supportsKeySystem(keySystem))
    {
        return ERROR_KEYSYSTEM_NOT_SUPPORTED;
    }
    return ERROR_NONE;
}

bool MediaKeysCapabilitiesBackend::getSupportedKeySystemVersion(const std::string &keySystem, std::string &version)
{
    if (!m_mediaKeysCapabilities)
    {
        return false;
    }
    return m_mediaKeysCapabilities->getSupportedKeySystemVersion(keySystem, version);
}

MediaKeysCapabilitiesBackend::MediaKeysCapabilitiesBackend()
{
    std::shared_ptr<firebolt::rialto::IMediaKeysCapabilitiesFactory> factory =
        firebolt::rialto::IMediaKeysCapabilitiesFactory::createFactory();
    if (!factory)
    {
        return;
    }

    m_mediaKeysCapabilities = factory->getMediaKeysCapabilities();
}

MediaKeysCapabilitiesBackend::~MediaKeysCapabilitiesBackend()
{
    m_mediaKeysCapabilities.reset();
}
