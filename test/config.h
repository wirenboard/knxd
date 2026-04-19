/* Minimal config.h for native test build (no autotools) */
#ifndef CONFIG_H
#define CONFIG_H

#define HAVE_SYS_TIME_H 1
#define HAVE_FMT_PRINTF 1

/* Use mbedTLS instead of OpenSSL for testing */
/* #undef HAVE_OPENSSL */
#define HAVE_IPSECURE 1

/* Disable platform-specific features */
/* #undef HAVE_SYSTEMD */
/* #undef HAVE_LINUX_LOWLATENCY */
/* #undef HAVE_LINUX_NETLINK */
/* #undef HAVE_WINDOWS_IPHELPER */
/* #undef HAVE_BSD_SOURCEINFO */
/* #undef HAVE_SOCKADDR_IN_LEN */
/* #undef HAVE_SA_SIZE */

/* Disable optional subsystems */
/* #undef HAVE_BUSMONITOR */
/* #undef HAVE_GROUPCACHE */
/* #undef HAVE_MANAGEMENT */

#define PACKAGE_VERSION "0.14.74-esp32"

#endif
