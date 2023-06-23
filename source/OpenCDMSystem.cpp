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

#include "OpenCDMSystem.h"

OpenCDMSystem::OpenCDMSystem(const char system[], const std::string &metadata)
    : m_keySystem(system),
      m_metadata(metadata), m_control{firebolt::rialto::IControlFactory::createFactory()->createControl()},
      m_messageDispatcher{std::make_shared<MessageDispatcher>()},
      m_cdmBackend{std::make_shared<CdmBackend>(m_keySystem, m_messageDispatcher)}
{
    firebolt::rialto::ApplicationState initialState;
    m_control->registerClient(m_cdmBackend, initialState);
    m_cdmBackend->initialize(initialState);
}

const std::string &OpenCDMSystem::keySystem() const
{
    return m_keySystem;
}

const std::string &OpenCDMSystem::Metadata() const
{
    return m_metadata;
}

OpenCDMSession *OpenCDMSystem::createSession(const LicenseType licenseType, OpenCDMSessionCallbacks *callbacks,
                                             void *userData, const std::string &initDataType,
                                             const std::vector<uint8_t> &initData) const
{
    return ActiveSessions::instance().create(m_cdmBackend, m_messageDispatcher, licenseType, callbacks, userData,
                                             initDataType, initData);
}

bool OpenCDMSystem::getDrmTime(uint64_t &drmTime) const
{
    if (!m_cdmBackend)
    {
        return false;
    }
    return m_cdmBackend->getDrmTime(drmTime);
}

bool OpenCDMSystem::getLdlSessionsLimit(uint32_t &ldlLimit) const
{
    if (!m_cdmBackend)
    {
        return false;
    }
    return m_cdmBackend->getLdlSessionsLimit(ldlLimit);
}

bool OpenCDMSystem::getKeyStoreHash(std::vector<unsigned char> &keyStoreHash) const
{
    if (!m_cdmBackend)
    {
        return false;
    }
    return m_cdmBackend->getKeyStoreHash(keyStoreHash);
}

bool OpenCDMSystem::getDrmStoreHash(std::vector<unsigned char> &drmStoreHash) const
{
    if (!m_cdmBackend)
    {
        return false;
    }
    return m_cdmBackend->getDrmStoreHash(drmStoreHash);
}

bool OpenCDMSystem::deleteKeyStore() const
{
    if (!m_cdmBackend)
    {
        return false;
    }
    return m_cdmBackend->deleteKeyStore();
}

bool OpenCDMSystem::deleteDrmStore() const
{
    if (!m_cdmBackend)
    {
        return false;
    }
    return m_cdmBackend->deleteDrmStore();
}
