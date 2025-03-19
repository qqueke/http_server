cmake_minimum_required(VERSION 3.20)

project(server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g -Wall")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INC_DIR ${CMAKE_SOURCE_DIR}/include)
set(BUILD_DIR ${CMAKE_BINARY_DIR}/build)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)

set(LS_QPACK_DIR ${LIB_DIR}/ls-qpack)
set(LS_HPACK_DIR ${LIB_DIR}/ls-hpack)
set(MSQUIC_DIR ${LIB_DIR}/msquic)

set(LS_QPACK_BUILD ${LS_QPACK_DIR}/build)
set(LS_HPACK_BUILD ${LS_HPACK_DIR}/build)
set(MSQUIC_BUILD ${MSQUIC_DIR}/build)

include_directories(${INC_DIR})
include_directories(${INC_DIR}/proto)
include_directories(${LS_QPACK_DIR})
include_directories(${LS_HPACK_DIR})
include_directories(${MSQUIC_DIR}/src/inc)

link_directories(${LS_QPACK_BUILD} ${LS_HPACK_BUILD} ${MSQUIC_BUILD}/bin/Release)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

add_library(protolib proto/database_service.proto)
target_link_libraries(protolib gRPC::grpc++)

target_include_directories(protolib PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)

protobuf_generate(TARGET protolib LANGUAGE cpp)

protobuf_generate(TARGET protolib LANGUAGE grpc GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc PLUGIN "protoc-gen-grpc=${grpc_cpp_plugin_location}")


set(SOURCES
    ${SRC_DIR}/main.cc
    ${SRC_DIR}/server.cc
    ${SRC_DIR}/router.cc
    ${SRC_DIR}/routes.cc
    ${SRC_DIR}/log.cc
    ${SRC_DIR}/codec.cc
    ${SRC_DIR}/http2_frame_builder.cc
    ${SRC_DIR}/http3_frame_builder.cc
    ${SRC_DIR}/http2_request_handler.cc
    ${SRC_DIR}/header_parser.cc
    ${SRC_DIR}/header_validator.cc
    ${SRC_DIR}/static_content_handler.cc
    ${SRC_DIR}/http3_request_handler.cc
    ${SRC_DIR}/transport.cc
    ${SRC_DIR}/tls_manager.cc
    ${SRC_DIR}/client.cc
    ${SRC_DIR}/utils.cc
    ${SRC_DIR}/tcp_server.cc
    ${SRC_DIR}/tcp_client.cc
    ${SRC_DIR}/quic_server.cc
    ${SRC_DIR}/quic_client.cc
    ${SRC_DIR}/database_client.cc
    ${SRC_DIR}/database_handler.cc
    ${SRC_DIR}/query_builder.cc
)

add_executable(server ${SOURCES})

target_link_libraries(server
    gtest
    gtest_main
    pthread
    ssl
    crypto
    z
    msquic
    ls-qpack
    ls-hpack
    protolib
)

# set(DB_CLIENT_SOURCES
#   ${SRC_DIR}/database_client.cc
#   ${SRC_DIR}/database_handler.cc
#   ${SRC_DIR}/query_builder.cc
# )
#
# add_executable(db_client ${DB_CLIENT_SOURCES})
#
# target_link_libraries(db_client protolib)

set(DB_SERVER_SOURCES
    ${SRC_DIR}/database_server.cc
    ${SRC_DIR}/database_tables.cc
    ${SRC_DIR}/transaction_manager.cc
    ${SRC_DIR}/database.cc
)

add_executable(db_server ${DB_SERVER_SOURCES})

target_link_libraries(db_server protolib)


# Generate a list of files that match the last argument and store to TEST_SOURCES
file(GLOB TEST_SOURCES "${TEST_DIR}/*.cc")

add_executable(tests ${TEST_SOURCES} ${SOURCES})

target_link_libraries(tests
    protolib
    gtest
    gtest_main
    pthread
    ssl
    crypto
    z
    msquic
    ls-qpack
    ls-hpack
)

add_test(NAME test COMMAND tests)
