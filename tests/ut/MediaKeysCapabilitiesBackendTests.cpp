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
#include "MediaKeysCapabilitiesMock.h"
#include <gtest/gtest.h>

using firebolt::rialto::MediaKeysCapabilitiesFactoryMock;
using firebolt::rialto::MediaKeysCapabilitiesMock;
using testing::_;
using testing::AtLeast;
using testing::Return;
using testing::StrictMock;

namespace
{
const std::string kKeySystem{"com.netflix.playready"};
} // namespace

class MediaKeysCapabilitiesBackendTests : public testing::Test
{
protected:
    std::shared_ptr<StrictMock<MediaKeysCapabilitiesFactoryMock>> m_mediaKeysCapabilitiesFactoryMock{
        std::dynamic_pointer_cast<StrictMock<MediaKeysCapabilitiesFactoryMock>>(
            firebolt::rialto::IMediaKeysCapabilitiesFactory::createFactory())};
    std::shared_ptr<StrictMock<MediaKeysCapabilitiesMock>> m_mediaKeysCapabilitiesMock{
        std::dynamic_pointer_cast<StrictMock<MediaKeysCapabilitiesMock>>(
            m_mediaKeysCapabilitiesFactoryMock->getMediaKeysCapabilities())};
};

TEST_F(MediaKeysCapabilitiesBackendTests, shouldGetSupportedKeySystems)
{
    const std::vector<std::string> kKeySystems{"a", "b"};
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, getSupportedKeySystems()).WillOnce(Return(kKeySystems));
    EXPECT_EQ(kKeySystems, MediaKeysCapabilitiesBackend::instance().getSupportedKeySystems());
}

TEST_F(MediaKeysCapabilitiesBackendTests, shouldNotSupportKeySystem)
{
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, supportsKeySystem(kKeySystem)).WillOnce(Return(false));
    EXPECT_EQ(ERROR_KEYSYSTEM_NOT_SUPPORTED, MediaKeysCapabilitiesBackend::instance().supportsKeySystem(kKeySystem));
}

TEST_F(MediaKeysCapabilitiesBackendTests, shouldSupportKeySystem)
{
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, supportsKeySystem(kKeySystem)).WillOnce(Return(true));
    EXPECT_EQ(ERROR_NONE, MediaKeysCapabilitiesBackend::instance().supportsKeySystem(kKeySystem));
}

TEST_F(MediaKeysCapabilitiesBackendTests, shouldFailToGetSupportedKeySystemVersion)
{
    std::string version{};
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, getSupportedKeySystemVersion(kKeySystem, _)).WillOnce(Return(false));
    EXPECT_FALSE(MediaKeysCapabilitiesBackend::instance().getSupportedKeySystemVersion(kKeySystem, version));
}

TEST_F(MediaKeysCapabilitiesBackendTests, shouldGetSupportedKeySystemVersion)
{
    std::string version{};
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, getSupportedKeySystemVersion(kKeySystem, _)).WillOnce(Return(true));
    EXPECT_TRUE(MediaKeysCapabilitiesBackend::instance().getSupportedKeySystemVersion(kKeySystem, version));
}

TEST_F(MediaKeysCapabilitiesBackendTests, shouldGetSupportedServerCertificate)
{
    EXPECT_CALL(*m_mediaKeysCapabilitiesMock, isServerCertificateSupported(kKeySystem)).WillOnce(Return(true));
    EXPECT_TRUE(MediaKeysCapabilitiesBackend::instance().isServerCertificateSupported(kKeySystem));
}
