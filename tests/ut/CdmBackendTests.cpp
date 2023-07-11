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

#include "CdmBackend.h"
#include "MediaKeysClientMock.h"
#include "MediaKeysMock.h"
#include <gtest/gtest.h>

using firebolt::rialto::MediaKeysFactoryMock;
using testing::ByMove;
using testing::Return;
using testing::StrictMock;

namespace firebolt::rialto
{
std::shared_ptr<IMediaKeysFactory> IMediaKeysFactory::createFactory()
{
    static auto factory{std::make_shared<StrictMock<MediaKeysFactoryMock>>()};
    return factory;
}
} // namespace firebolt::rialto

namespace
{
const std::string kKeySystem{"com.netflix.playready"};
} // namespace

class CdmBackendTests : public testing::Test
{
public:
    CdmBackendTests() = default;
    ~CdmBackendTests() override = default;

protected:
    std::shared_ptr<StrictMock<firebolt::rialto::MediaKeysClientMock>> m_mediaKeysClientMock{
        std::make_shared<StrictMock<firebolt::rialto::MediaKeysClientMock>>()};
    std::shared_ptr<StrictMock<MediaKeysFactoryMock>> m_mediaKeysFactoryMock{
        std::dynamic_pointer_cast<StrictMock<MediaKeysFactoryMock>>(firebolt::rialto::IMediaKeysFactory::createFactory())};
    CdmBackend m_sut{kKeySystem, m_mediaKeysClientMock};
};

TEST_F(CdmBackendTests, ShouldChangeStateToInactive)
{
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::INACTIVE);
}

TEST_F(CdmBackendTests, ShouldChangeStateToRunning)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
}

TEST_F(CdmBackendTests, ShouldDoNothingWhenSwitchedToTheSameState)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
}

TEST_F(CdmBackendTests, ShouldInitializeMediaKeysWhenSwitchedToRunningAgain)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::INACTIVE);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::RUNNING);
}

TEST_F(CdmBackendTests, ShouldNotInitializeTwice)
{
    m_sut.notifyApplicationState(firebolt::rialto::ApplicationState::INACTIVE);
    EXPECT_TRUE(m_sut.initialize(firebolt::rialto::ApplicationState::INACTIVE));
}

TEST_F(CdmBackendTests, ShouldInitializeWithoutMediaKeysCreationInInactiveState)
{
    EXPECT_TRUE(m_sut.initialize(firebolt::rialto::ApplicationState::INACTIVE));
}

TEST_F(CdmBackendTests, ShouldFailToInitializeInRunningState)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem)).WillOnce(Return(nullptr));
    EXPECT_FALSE(m_sut.initialize(firebolt::rialto::ApplicationState::RUNNING));
}

TEST_F(CdmBackendTests, ShouldInitializeInRunningState)
{
    ASSERT_TRUE(m_mediaKeysFactoryMock);
    EXPECT_CALL(*m_mediaKeysFactoryMock, createMediaKeys(kKeySystem))
        .WillOnce(Return(ByMove(std::make_unique<StrictMock<firebolt::rialto::MediaKeysMock>>())));
    EXPECT_TRUE(m_sut.initialize(firebolt::rialto::ApplicationState::RUNNING));
}
