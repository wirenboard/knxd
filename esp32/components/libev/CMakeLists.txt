# Component: libev event loop for ESP32
#
# libev is compiled as a single-file library (ev.c).
# Download ev.c and ev.h from http://dist.schmorp.de/libev/
# and place them in this directory.
#
# ESP32 configuration: select() backend only, no signals/child/stat.

idf_component_register(
    SRCS "ev.c"
    INCLUDE_DIRS "."
    REQUIRES lwip
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    EV_STANDALONE=1
    EV_USE_SELECT=1
    EV_USE_POLL=0
    EV_USE_EPOLL=0
    EV_USE_KQUEUE=0
    EV_USE_PORT=0
    EV_SIGNAL_ENABLE=0
    EV_CHILD_ENABLE=0
    EV_STAT_ENABLE=0
    EV_EMBED_ENABLE=0
    EV_IDLE_ENABLE=1
    EV_PREPARE_ENABLE=0
    EV_CHECK_ENABLE=0
    EV_FORK_ENABLE=0
    EV_CLEANUP_ENABLE=0
    EV_ASYNC_ENABLE=1
    EV_MULTIPLICITY=0
)
