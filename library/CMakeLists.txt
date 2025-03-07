#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2023 Sky UK
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

find_package(Rialto 1.0 REQUIRED)

add_library(ocdmRialto

        SHARED
        source/open_cdm.cpp
        source/open_cdm_adapter.cpp
        source/open_cdm_ext.cpp

        source/ActiveSessions.cpp
        source/CdmBackend.cpp
        source/Logger.cpp
        source/MediaKeysCapabilitiesBackend.cpp
        source/OpenCDMSessionPrivate.cpp
        source/OpenCDMSystemPrivate.cpp
        source/MessageDispatcher.cpp
        source/RialtoGStreamerEMEProtectionMetadata.cpp)

set_target_properties(
        ocdmRialto
        PROPERTIES LINK_FLAGS "-Wl,--unresolved-symbols=report-all"
                   SOVERSION  ${PROJECT_VERSION_MAJOR}
                   VERSION    ${CMAKE_PROJECT_VERSION}
        )

target_include_directories(
        ocdmRialto

        PRIVATE
        include
        ${CMAKE_INCLUDE_PATH}
        ${CMAKE_INCLUDE_PATH}/rialto
        ${GStreamerApp_INCLUDE_DIRS}
        )

target_link_libraries(
        ocdmRialto

        PRIVATE
        Rialto::RialtoClient
        ${GStreamerApp_LIBRARIES}
        )

include( GNUInstallDirs )

set (LIB_RIALTO_OCDM_PUBLIC_HEADERS
        include/RialtoGStreamerEMEProtectionMetadata.h
)

configure_file(ocdmRialto.pc.in ocdmRialto.pc @ONLY)

install (
        FILES ${LIB_RIALTO_OCDM_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rialto
)

install(TARGETS ocdmRialto LIBRARY
        DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES "${CMAKE_BINARY_DIR}/library/ocdmRialto.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# Retrieve the commit ID
execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} 
    RESULT_VARIABLE RESULT 
    OUTPUT_VARIABLE SRCREV 
    OUTPUT_STRIP_TRAILING_WHITESPACE 
)

if(RESULT)
    message("Failed to get git commit ID: ${RESULT}")
endif()

# Retrieve release tag(s)
execute_process(
    COMMAND bash -c "git tag --points-at ${SRCREV} | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}  
    OUTPUT_VARIABLE TAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE 
)
string(REPLACE "\n" ", " TAGS "${TAGS}")

if(NOT TAGS STREQUAL "")
    set(TAGS ${TAGS})
endif() 

# Preprocesser Variable
add_compile_definitions(SRCREV="${SRCREV}")
add_compile_definitions(TAGS="${TAGS}")
