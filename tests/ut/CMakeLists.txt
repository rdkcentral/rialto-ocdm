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

pkg_check_modules( GStreamerApp REQUIRED IMPORTED_TARGET gstreamer-app-1.0 gstreamer-pbutils-1.0 gstreamer-audio-1.0)

# Retrieve the commit ID
execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} 
    RESULT_VARIABLE RESULT 
    OUTPUT_VARIABLE COMMIT_ID 
    OUTPUT_STRIP_TRAILING_WHITESPACE 
)

if(RESULT)
    message("Failed to get git commit ID: ${RESULT}")
endif()

# Preprocesser Variable
add_compile_definitions(COMMIT_ID="${COMMIT_ID}")

add_library(
        ocdmRialtoTestLib

        STATIC
        ${CMAKE_SOURCE_DIR}/library/source/open_cdm.cpp
        ${CMAKE_SOURCE_DIR}/library/source/open_cdm_adapter.cpp
        ${CMAKE_SOURCE_DIR}/library/source/open_cdm_ext.cpp

        ${CMAKE_SOURCE_DIR}/library/source/ActiveSessions.cpp
        ${CMAKE_SOURCE_DIR}/library/source/CdmBackend.cpp
        ${CMAKE_SOURCE_DIR}/library/source/Logger.cpp
        ${CMAKE_SOURCE_DIR}/library/source/MediaKeysCapabilitiesBackend.cpp
        ${CMAKE_SOURCE_DIR}/library/source/OpenCDMSessionPrivate.cpp
        ${CMAKE_SOURCE_DIR}/library/source/OpenCDMSystemPrivate.cpp
        ${CMAKE_SOURCE_DIR}/library/source/MessageDispatcher.cpp
        ${CMAKE_SOURCE_DIR}/library/source/RialtoGStreamerEMEProtectionMetadata.cpp
)

target_include_directories(
        ocdmRialtoTestLib

        PUBLIC
        ${CMAKE_SOURCE_DIR}/library/include
        ${CMAKE_SOURCE_DIR}/tests/third-party/include

        PRIVATE
        ${GStreamerApp_INCLUDE_DIRS}
        )

target_link_libraries(
        ocdmRialtoTestLib

        PRIVATE
        RialtoOcdmMocks
        ocdmRialtoThirdParty
        ${GStreamerApp_LIBRARIES}
)

add_gtests (
        RialtoOcdmUnitTests

        # gtest code
        ActiveSessionsTests.cpp
        CdmBackendTests.cpp
        MediaKeysCapabilitiesBackendTests.cpp
        MessageDispatcherTests.cpp
        OpenCdmAdapterTests.cpp
        OpenCdmExtTests.cpp
        OpenCdmSessionTests.cpp
        OpenCdmSystemTests.cpp
        OpenCdmTests.cpp
        )

target_include_directories(
        RialtoOcdmUnitTests

        PRIVATE
        $<TARGET_PROPERTY:RialtoOcdmMocks,INTERFACE_INCLUDE_DIRECTORIES>
        $<TARGET_PROPERTY:ocdmRialtoTestLib,INTERFACE_INCLUDE_DIRECTORIES>
        ${GStreamerApp_INCLUDE_DIRS}

        mocks
)

target_link_libraries(
        RialtoOcdmUnitTests

        ocdmRialtoThirdParty
        ocdmRialtoTestLib
        ${GStreamerApp_LIBRARIES}
)
