project(secure-server C)
cmake_minimum_required(VERSION 2.8)
set( CMAKE_VERBOSE_MAKEFILE on )
aux_source_directory(. SRC_LIST)

add_executable(secure-server "server.c")
add_executable(secure-client "client.c")
set (LIBS  "-lssl -lcrypto")
target_link_libraries(secure-server ${LIBS})
target_link_libraries(secure-client ${LIBS})


