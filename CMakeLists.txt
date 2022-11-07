#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2022 Sky UK
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

cmake_minimum_required( VERSION 3.10 )
project( ocdmRialto LANGUAGES C CXX VERSION 1.0 )

# Add our local cmake directory to search for components
set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake )

set( CMAKE_CXX_STANDARD 14 )

set( CMAKE_CXX_STANDARD_REQUIRED ON )
include( CheckCXXCompilerFlag )

find_package( Rialto REQUIRED )
find_package( ocdm REQUIRED )
find_package( WPEFramework REQUIRED )
find_package( PkgConfig REQUIRED )
pkg_check_modules( GStreamerApp REQUIRED IMPORTED_TARGET gstreamer-app-1.0 )

set(LIB_OCDM_RIALTO_SOURCES
        source/open_cdm.cpp
        source/open_cdm_adapter.cpp
        source/open_cdm_ext.cpp

        source/ActiveSessions.cpp
        source/CdmBackend.cpp
        source/OpenCDMSession.cpp
        source/MediaKeysClient.cpp
        source/Utils.cpp
        source/RialtoGStreamerEMEProtectionMetadata.cpp)

add_library(ocdmRialto SHARED ${LIB_OCDM_RIALTO_SOURCES} )

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
install (
        FILES ${LIB_RIALTO_OCDM_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rialto
)

install(TARGETS ocdmRialto LIBRARY
        DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/ocdmRialto.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")


