/*
 * Compatibility header for building SSSD's murmurhash3.c standalone.
 * Provides the minimal defines normally set by SSSD's autotools config.
 */

#ifndef SSSD_MC_COMPAT_H
#define SSSD_MC_COMPAT_H

/* Satisfy murmurhash3.c's #include "config.h" */
#define HAVE_ENDIAN_H 1

/* Satisfy murmurhash3.c's SSS_ATTRIBUTE_FALLTHROUGH */
#if __GNUC__ >= 7
#define SSS_ATTRIBUTE_FALLTHROUGH __attribute__((fallthrough))
#else
#define SSS_ATTRIBUTE_FALLTHROUGH ((void)0)
#endif

#endif /* SSSD_MC_COMPAT_H */
