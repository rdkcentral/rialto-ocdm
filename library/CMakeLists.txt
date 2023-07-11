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

find_package( Rialto REQUIRED )
find_package( ocdm REQUIRED )

set(LIB_OCDM_RIALTO_SOURCES
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
        source/Utils.cpp
        source/RialtoGStreamerEMEProtectionMetadata.cpp)

add_library(ocdmRialto SHARED ${LIB_OCDM_RIALTO_SOURCES} )

set_target_properties(
        ocdmRialto
        PROPERTIES LINK_FLAGS "-Wl,--unresolved-symbols=report-all"
                   SOVERSION  ${PROJECT_VERSION_MAJOR}
                   VERSION    ${CMAKE_PROJECT_VERSION}
        )

target_include_directories(
        ocdmRialto

        PUBLIC
        $<INSTALL_INTERFACE:include/rialto>

        PRIVATE
        include
        ${RIALTO_INCLUDE_DIR}
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
    OUTPUT_VARIABLE COMMIT_ID 
    OUTPUT_STRIP_TRAILING_WHITESPACE 
)

if(RESULT)
    message("Failed to get git commit ID: ${RESULT}")
endif()

# Preprocesser Variable
add_compile_definitions(COMMIT_ID="${COMMIT_ID}")