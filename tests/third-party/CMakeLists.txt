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

# Default to 'master' if branch is not specified
if(BUILD_BRANCH)
    message("======= Branch specified, using '${BUILD_BRANCH}' branch =======")
else()
    set(BUILD_BRANCH "master")
    message("======= No branch specified, using 'master' branch as default =======")
endif()

# Function to download the relevant files, and to check if the file downloaded is empty 
function(downloadAndCheck URL FILE)
    if((FILE MATCHES "open_cdm_adapter.h") OR (FILE MATCHES "open_cdm_ext.h") OR (FILE MATCHES "open_cdm.h")) # Special case for the different path files
        set(FILE_PATH ${CMAKE_SOURCE_DIR}/tests/third-party/include/opencdm/${FILE})
    else()
        set(FILE_PATH ${CMAKE_SOURCE_DIR}/tests/third-party/include/${FILE})
    endif()

    if(NOT EXISTS ${FILE_PATH})
        file(DOWNLOAD ${URL} ${FILE_PATH})
        message("Downloaded ${FILE}")
        
        # If the file is empty
        file(READ ${FILE_PATH} fileContents)
        if("${fileContents}" STREQUAL "")
            message(FATAL_ERROR "The downloaded ${FILE} file is empty!")
        endif()
    endif()
endfunction()


# List of files to download
set(FILE_LIST
    open_cdm_adapter.h
    open_cdm_ext.h
    open_cdm.h
    ControlCommon.h
    IControl.h
    IControlClient.h
    IMediaKeys.h
    IMediaKeysCapabilities.h
    IMediaKeysClient.h
    MediaCommon.h
)

# Loop through the list and call the function
foreach(FILE_NAME ${FILE_LIST})
    if((FILE_NAME MATCHES "open_cdm_ext.h") OR (FILE_NAME MATCHES "open_cdm.h")) # Special case for header file as the path is different
        set(BASE_URL https://raw.githubusercontent.com/rdkcentral/ThunderClientLibraries/master/Source/ocdm/)
    elseif(FILE_NAME MATCHES "open_cdm_adapter.h") # Special case for header file as the path is different
        set(BASE_URL https://raw.githubusercontent.com/rdkcentral/ThunderClientLibraries/master/Source/ocdm/adapter/)
    else()
        set(BASE_URL https://raw.githubusercontent.com/rdkcentral/rialto/${BUILD_BRANCH}/media/public/include/)
    endif()

    downloadAndCheck(${BASE_URL}${FILE_NAME} ${FILE_NAME})
endforeach()

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
