include_directories (${CMAKE_CURRENT_SOURCE_DIR})

set (SRCS
     echo-server.c)

add_executable (echo-server ${SRCS})
