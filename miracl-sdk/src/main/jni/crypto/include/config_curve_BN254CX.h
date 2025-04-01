#ifndef CONFIG_CURVE_BN254CX_H
#define CONFIG_CURVE_BN254CX_H

#include"amcl.h"
#include"config_field_BN254CX.h"

// ECP stuff

#define CURVETYPE_BN254CX WEIERSTRASS
#define PAIRING_FRIENDLY_BN254CX BN
#define CURVE_SECURITY_BN254CX 128


#if PAIRING_FRIENDLY_BN254CX != NOT
//#define USE_GLV_BN254CX	  /**< Note this method is patented (GLV), so maybe you want to comment this out */
//#define USE_GS_G2_BN254CX /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_BN254CX /**< Not patented, so probably safe to always use this */

#define POSITIVEX 0
#define NEGATIVEX 1

#define SEXTIC_TWIST_BN254CX D_TYPE
#define SIGN_OF_X_BN254CX NEGATIVEX

#endif

#if CURVE_SECURITY_BN254CX == 128
#define AESKEY_BN254CX 16 /**< Symmetric Key size - 128 bits */
#define HASH_TYPE_BN254CX SHA256  /**< Hash type */
#endif

#if CURVE_SECURITY_BN254CX == 192
#define AESKEY_BN254CX 24 /**< Symmetric Key size - 192 bits */
#define HASH_TYPE_BN254CX SHA384  /**< Hash type */
#endif

#if CURVE_SECURITY_BN254CX == 256
#define AESKEY_BN254CX 32 /**< Symmetric Key size - 256 bits */
#define HASH_TYPE_BN254CX SHA512  /**< Hash type */
#endif



#endif
