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

#ifndef OCDM_SESSIONS_CALLBACKS_MOCK_H_
#define OCDM_SESSIONS_CALLBACKS_MOCK_H_

#include "OpenCDMSession.h"
#include <gmock/gmock.h>

class OcdmSessionsCallbacksMock
{
    OcdmSessionsCallbacksMock() = default;
    ~OcdmSessionsCallbacksMock() = default;

public:
    static OcdmSessionsCallbacksMock &instance();

    MOCK_METHOD(void, processChallengeCallback,
                (OpenCDMSession * session, void *userData, const char url[], const uint8_t challenge[],
                 const uint16_t challengeLength));
    MOCK_METHOD(void, keyUpdateCallback,
                (OpenCDMSession * session, void *userData, const uint8_t keyId[], const uint8_t length));
    MOCK_METHOD(void, errorMessageCallback, (OpenCDMSession * session, void *userData, const char message[]));
    MOCK_METHOD(void, keysUpdatedCallback, (const OpenCDMSession *session, void *userData));
};

void processChallengeCallback(OpenCDMSession *session, void *userData, const char url[], const uint8_t challenge[],
                              const uint16_t challengeLength);
void keyUpdateCallback(OpenCDMSession *session, void *userData, const uint8_t keyId[], const uint8_t length);
void errorMessageCallback(OpenCDMSession *session, void *userData, const char message[]);
void keysUpdatedCallback(const OpenCDMSession *session, void *userData);

#endif // OCDM_SESSIONS_CALLBACKS_MOCK_H_
