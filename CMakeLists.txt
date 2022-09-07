# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

project(h4bcm-wireshark-plugin C CXX)

cmake_minimum_required(VERSION 3.5)
set(CMAKE_BACKWARDS_COMPATIBILITY 3.5)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

MESSAGE(${CMAKE_MODULE_PATH})

find_package(Wireshark 3.4)

if(Wireshark_FOUND)

  MESSAGE(STATUS "Wireshark 3.4 libraries found in ${Wireshark_LIB_DIR}, performing a stand-alone plug-in build.")

  if(NOT CMAKE_INSTALL_LIBDIR )
    set(CMAKE_INSTALL_LIBDIR ~/.local/lib/wireshark/plugins/${Wireshark_VERSION_MAJOR}.${Wireshark_VERSION_MINOR}/epan)
  endif(NOT CMAKE_INSTALL_LIBDIR )
  MESSAGE(STATUS "Plug-in will be installed in: ${CMAKE_INSTALL_LIBDIR}")

  INCLUDE(UseMakePluginReg)

  set(GLIB2_MIN_VERSION 2.4.0)

  find_package(GLIB2)
  include_directories (${GLIB2_INCLUDE_DIRS})

  include_directories (${Wireshark_INCLUDE_DIR})

  IF(APPLE)
    LINK_DIRECTORIES(/usr/local/lib)
  ENDIF()

  set(LINK_MODE_LIB SHARED)
  set(LINK_MODE_MODULE MODULE)

else(Wireshark_FOUND)

  MESSAGE(STATUS "Wireshark 3.4 libraries not found, performing an in-tree Wireshark plug-in build.")

  include(WiresharkPlugin)

  # Plugin name and version info (major minor micro extra)
  set_module_info(h4bcm 1 1 0 0)

endif(Wireshark_FOUND)

set(DISSECTOR_SRC
	packet-h4bcm.c
	packet-btbrlmp.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

if(Wireshark_FOUND)

  add_library(h4bcm ${LINK_MODE_MODULE}
                  ${PLUGIN_FILES}
                  ${PLUGIN_RC_FILE}
  )

  set_target_properties(h4bcm PROPERTIES
          PREFIX ""
          LINK_FLAGS "${WS_LINK_FLAGS}"
          FOLDER "Plugins"
  )

  link_directories(${Wireshark_LIB_DIR})

  target_link_libraries(h4bcm wireshark)

  install(TARGETS h4bcm
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

else(Wireshark_FOUND)

  add_plugin_library(h4bcm epan)

  target_link_libraries(h4bcm epan)

  install_plugin(h4bcm epan)

  file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
  CHECKAPI(
	NAME
	  h4bcm
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
  )

endif(Wireshark_FOUND)
#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
