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

#include <CdmBackend.h>
#include <memory>
#include <string>

struct OpenCDMSystem
{
    OpenCDMSystem(const char system[], const std::string &metadata, const std::shared_ptr<CdmBackend> &cdmBackend)
        : _keySystem(system), _metadata(metadata), _cdmBackend(cdmBackend)
    {
    }
    ~OpenCDMSystem() { _cdmBackend->destroyMediaKeys(); };
    OpenCDMSystem(const OpenCDMSystem &) = default;
    OpenCDMSystem(OpenCDMSystem &&) = default;
    OpenCDMSystem &operator=(OpenCDMSystem &&) = default;
    OpenCDMSystem &operator=(const OpenCDMSystem &) = default;
    const std::string &keySystem() const { return _keySystem; }
    const std::string &Metadata() const { return _metadata; }
    const std::shared_ptr<CdmBackend> &getCdmBackend() const { return _cdmBackend; }

private:
    std::string _keySystem;
    std::string _metadata;
    std::shared_ptr<CdmBackend> _cdmBackend;
};