cmake_minimum_required(VERSION 3.16)

# ESP-IDF project: KNX TP → KNX/IP Secure tunnel
# Build: idf.py build
# Flash: idf.py -p /dev/ttyUSB0 flash monitor

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(knxd_esp32)
