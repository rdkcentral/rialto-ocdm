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

#ifndef FIREBOLT_RIALTO_CONTROL_MOCK_H_
#define FIREBOLT_RIALTO_CONTROL_MOCK_H_

#include "IControl.h"
#include <gmock/gmock.h>
#include <memory>

namespace firebolt::rialto
{
class ControlFactoryMock : public IControlFactory
{
public:
    MOCK_METHOD(std::shared_ptr<IControl>, createControl, (), (const, override));
};

class ControlMock : public IControl
{
public:
    MOCK_METHOD(bool, registerClient, (std::weak_ptr<IControlClient> client, ApplicationState &appState), (override));
};
} // namespace firebolt::rialto

#endif // FIREBOLT_RIALTO_CONTROL_MOCK_H_
