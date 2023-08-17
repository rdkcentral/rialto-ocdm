#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2023 Sky UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set( CMAKE_CXX_STANDARD 17 )

set( CMAKE_CXX_STANDARD_REQUIRED ON )
include( CheckCXXCompilerFlag )

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/IMediaKeys.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/IMediaKeys.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/IMediaKeys.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/IMediaKeysClient.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/IMediaKeysClient.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/IMediaKeysClient.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/MediaCommon.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/MediaCommon.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/MediaCommon.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/ControlCommon.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/ControlCommon.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/ControlCommon.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/IControlClient.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/IControlClient.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/IControlClient.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/IControl.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/IControl.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/IControl.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/IMediaKeysCapabilities.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/rialto/master/media/public/include/IMediaKeysCapabilities.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/IMediaKeysCapabilities.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/open_cdm.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/ThunderClientLibraries/master/Source/ocdm/open_cdm.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/open_cdm.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/open_cdm_ext.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/ThunderClientLibraries/master/Source/ocdm/open_cdm_ext.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/open_cdm_ext.h)
endif()

if (NOT EXISTS ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/open_cdm_adapter.h)
    file(DOWNLOAD
        https://raw.githubusercontent.com/rdkcentral/ThunderClientLibraries/master/Source/ocdm/adapter/open_cdm_adapter.h
        ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/open_cdm_adapter.h)
endif()

add_library(
    ocdmRialtoThirdParty

    STATIC

    source/ControlFactory.cpp
    source/MediaKeysCapabilitiesFactory.cpp
    source/MediaKeysFactory.cpp
    source/OcdmSessionsCallbacks.cpp
)

target_include_directories(
    ocdmRialtoThirdParty

    PUBLIC
    include

    PRIVATE
    ${CMAKE_SOURCE_DIR}/library/include
    $<TARGET_PROPERTY:RialtoOcdmMocks,INTERFACE_INCLUDE_DIRECTORIES>
)

target_link_libraries(
    ocdmRialtoThirdParty

    PRIVATE
    RialtoOcdmMocks
    GoogleTest::gmock
)
