/*
 * config.h for ESP32 build (replaces autotools-generated config.h)
 *
 * This file is included by knxd sources via -include or include path priority.
 * It defines the feature flags that autotools would normally set.
 */
#ifndef CONFIG_H
#define CONFIG_H

/* Package info */
#define PACKAGE_VERSION "0.14.74-esp32"
#define PACKAGE_STRING "knxd 0.14.74-esp32"

/* System headers available on ESP-IDF */
#define HAVE_SYS_TIME_H 1

/* IP Secure: use mbedTLS (not OpenSSL) */
#define HAVE_IPSECURE 1
/* #undef HAVE_OPENSSL */

/* Enable TPUART backend */
#define HAVE_TPUART 1

/* Enable EIBnet/IP tunnel server */
#define HAVE_EIBNETIPTUNNEL 1

/* Enable bus monitor (TunChannel supports it) */
#define HAVE_BUSMONITOR 1

/* Disable unused subsystems */
/* #undef HAVE_MANAGEMENT */
/* #undef HAVE_GROUPCACHE */
/* #undef HAVE_USB */
/* #undef HAVE_FT12 */

/* Disable Linux-specific features */
/* #undef HAVE_SYSTEMD */
/* #undef HAVE_LINUX_LOWLATENCY */
/* #undef HAVE_LINUX_NETLINK */

/* Not on Windows or BSD */
/* #undef HAVE_WINDOWS_IPHELPER */
/* #undef HAVE_BSD_SOURCEINFO */
/* #undef HAVE_SOCKADDR_IN_LEN */
/* #undef HAVE_SA_SIZE */

/* fmt library — on ESP32 we bundle fmt headers */
#define HAVE_FMT_PRINTF 1

#endif
