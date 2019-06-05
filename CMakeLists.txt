cmake_minimum_required (VERSION 2.8.11)
project (freebsd-aio-echo)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
     "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

add_subdirectory (src)
