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

#ifndef I_MESSAGE_DISPATCHER_H_
#define I_MESSAGE_DISPATCHER_H_

#include <IMediaKeysClient.h>
#include <memory>

class IMessageDispatcherClient
{
public:
    virtual ~IMessageDispatcherClient() = default;
};

class IMessageDispatcher
{
public:
    virtual ~IMessageDispatcher() = default;
    virtual std::unique_ptr<IMessageDispatcherClient> createClient(firebolt::rialto::IMediaKeysClient *client) = 0;
};

#endif // I_MESSAGE_DISPATCHER_H_
