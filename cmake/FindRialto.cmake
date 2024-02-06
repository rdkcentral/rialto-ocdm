#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2024 Sky UK
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

#############
# NOTE
# NOTE: This file is a copy of gstreamer/cmake/FindRialto.cmake
# NOTE: Please keep these two files "in step"
# NOTE: ...except for the different licence
# NOTE
#############

# - Try to find the Rialto library.
#
# The following are set after configuration is done:
#  RIALTO_FOUND
#  RIALTO_INCLUDE_DIRS
#  RIALTO_LIBRARY_DIRS
#  RIALTO_LIBRARIES
find_path( RIALTO_INCLUDE_DIR NAMES IMediaPipeline.h PATH_SUFFIXES rialto)
find_library( RIALTO_LIBRARY NAMES libRialtoClient.so RialtoClient )

#message( "RIALTO_INCLUDE_DIR include dir = ${RIALTO_INCLUDE_DIR}" )
#message( "RIALTO_LIBRARY lib = ${RIALTO_LIBRARY}" )

include( FindPackageHandleStandardArgs )

# Handle the QUIETLY and REQUIRED arguments and set the RIALTO_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args( RIALTO DEFAULT_MSG
        RIALTO_LIBRARY RIALTO_INCLUDE_DIR )

mark_as_advanced( RIALTO_INCLUDE_DIR RIALTO_LIBRARY )

if( RIALTO_FOUND )
    set( RIALTO_LIBRARIES ${RIALTO_LIBRARY} )
    set( RIALTO_INCLUDE_DIRS ${RIALTO_INCLUDE_DIR} )
endif()

if( RIALTO_FOUND AND NOT TARGET Rialto::RialtoClient )
    add_library( Rialto::RialtoClient SHARED IMPORTED )
    set_target_properties( Rialto::RialtoClient PROPERTIES
            IMPORTED_LOCATION "${RIALTO_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${RIALTO_INCLUDE_DIR}" )
endif()
