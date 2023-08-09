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
project( ocdmRialto LANGUAGES C CXX VERSION 1.0.0 )

# Add our local cmake directory to search for components
set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake )

set( CMAKE_CXX_STANDARD 17 )

set( CMAKE_CXX_STANDARD_REQUIRED ON )
include( CheckCXXCompilerFlag )

add_compile_options(-Wall -Werror)

# RIALTO-197: deprecated-declarations error in the latest stable2 for gstreamer.
# Should be removed once the issue is fixed.
add_compile_options(
  "-Wno-deprecated-declarations"
)

find_package( PkgConfig REQUIRED )
find_package( Threads REQUIRED )

pkg_check_modules( GStreamerApp REQUIRED IMPORTED_TARGET gstreamer-app-1.0 )

if ( RIALTO_ENABLE_DECRYPT_BUFFER )
    add_compile_definitions( RIALTO_ENABLE_DECRYPT_BUFFER )
endif()

# Config and target for building the unit tests
if( NOT CMAKE_BUILD_FLAG STREQUAL "UnitTests" )
    add_subdirectory(library)
else() # UnitTests
    include( cmake/googletest.cmake )

    add_subdirectory( tests/third-party EXCLUDE_FROM_ALL )
    add_subdirectory( tests/mocks EXCLUDE_FROM_ALL )
    add_subdirectory( tests/ut EXCLUDE_FROM_ALL )
endif()
