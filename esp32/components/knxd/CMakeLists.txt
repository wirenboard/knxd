# Component: knxd core library
# References the original knxd source files via relative paths.

set(KNXD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../../src")

set(KNXD_LIBSERVER_SRCS
    ${KNXD_SRC}/libserver/apdu.cpp
    ${KNXD_SRC}/libserver/cemi.cpp
    ${KNXD_SRC}/libserver/client.cpp
    ${KNXD_SRC}/libserver/cm_ip.cpp
    ${KNXD_SRC}/libserver/cm_tp1.cpp
    ${KNXD_SRC}/libserver/common.cpp
    ${KNXD_SRC}/libserver/eibnetip.cpp
    ${KNXD_SRC}/libserver/eibnetserver.cpp
    ${KNXD_SRC}/libserver/emi.cpp
    ${KNXD_SRC}/libserver/inetserver.cpp
    ${KNXD_SRC}/libserver/ipsecure.cpp
    ${KNXD_SRC}/libserver/ipsupport.cpp
    ${KNXD_SRC}/libserver/link.cpp
    ${KNXD_SRC}/libserver/llserial.cpp
    ${KNXD_SRC}/libserver/lltcp.cpp
    ${KNXD_SRC}/libserver/lowlatency.cpp
    ${KNXD_SRC}/libserver/lowlevel.cpp
    ${KNXD_SRC}/libserver/lpdu.cpp
    ${KNXD_SRC}/libserver/npdu.cpp
    ${KNXD_SRC}/libserver/retry.cpp
    ${KNXD_SRC}/libserver/router.cpp
    ${KNXD_SRC}/libserver/server.cpp
    ${KNXD_SRC}/libserver/systemdserver.cpp
    ${KNXD_SRC}/libserver/tcptunserver.cpp
    ${KNXD_SRC}/libserver/tpdu.cpp
    ${KNXD_SRC}/libserver/trace.cpp
    ${KNXD_SRC}/libserver/tunchannel.cpp
)

set(KNXD_COMMON_SRCS
    ${KNXD_SRC}/common/inifile.cpp
    ${KNXD_SRC}/common/inih.c
    ${KNXD_SRC}/common/iobuf.cpp
)

set(KNXD_BACKEND_SRCS
    ${KNXD_SRC}/backend/log.cpp
    ${KNXD_SRC}/backend/nat.cpp
    ${KNXD_SRC}/backend/tpuart.cpp
    ${KNXD_SRC}/backend/fpace.cpp
    ${KNXD_SRC}/backend/fqueue.cpp
)

idf_component_register(
    SRCS ${KNXD_LIBSERVER_SRCS} ${KNXD_COMMON_SRCS} ${KNXD_BACKEND_SRCS}
    INCLUDE_DIRS
        ${KNXD_SRC}/libserver
        ${KNXD_SRC}/common
        ${KNXD_SRC}/backend
        ${KNXD_SRC}/include
    REQUIRES mbedtls driver esp_event platform libev
)

# Use the platform config.h instead of autotools-generated one
target_include_directories(${COMPONENT_LIB} BEFORE PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/../platform"
)
