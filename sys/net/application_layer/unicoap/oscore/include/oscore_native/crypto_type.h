/*
 * SPDX-FileCopyrightText: 2026 Lukas Sebrantke
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @file
 * @brief   libOSCORE native cryptography types for RIOT
 *
 * @ingroup net_unicoap_oscore
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Type of COSE AEAD algorithms
 *
 * This backend only supports the numerical COSE algorithm identifiers.
 */
typedef int32_t oscore_crypto_aeadalg_t;

/**
 * @brief Type of COSE HKDF algorithms
 *
 * This backend only supports the numerical COSE algorithm identifiers.
 */
typedef int32_t oscore_crypto_hkdfalg_t;

/**
 * @brief Error type of cryptography operations
 *
 * `false` means success, `true` means error.
 */
typedef bool oscore_cryptoerr_t;

/**
 * @brief Maximum AEAD key length supported by this backend
 *
 * Large enough for AES-128 and ChaCha20 (both 32 bytes).
 */
#define OSCORE_CRYPTO_AEAD_KEY_MAXLEN (32U)

/**
 * @brief Maximum AEAD IV/nonce length supported by this backend
 *
 * Large enough for the 13 byte AES-CCM nonce and the 12 byte ChaCha20 nonce.
 */
#define OSCORE_CRYPTO_AEAD_IV_MAXLEN (13U)

#ifndef OSCORE_CRYPTO_AAD_MAXLEN
/**
 * @brief Maximum size of the additional authenticated data (AAD)
 *
 * OSCORE's AAD consists of the external AAD plus the serialized OSCORE
 * option, the request ID and the (optionally present) class I options. 128
 * bytes is plenty for typical deployments; raise this if class I options are
 * used.
 */
#define OSCORE_CRYPTO_AAD_MAXLEN (128U)
#endif

/**
 * @brief State of an ongoing AEAD operation
 *
 * Buffers the additional authenticated data and the key until the ciphertext
 * is available, because the underlying implementations take the full AAD in a
 * single call.
 */
typedef struct {
    /** @brief Buffered additional authenticated data */
    uint8_t aad[OSCORE_CRYPTO_AAD_MAXLEN];

    /** @brief Total number of AAD bytes declared by libOSCORE */
    size_t aad_len;

    /** @brief Number of AAD bytes received so far */
    size_t aad_received;

    /** @brief Key copy */
    uint8_t key[OSCORE_CRYPTO_AEAD_KEY_MAXLEN];

    /** @brief IV/nonce copy */
    uint8_t iv[OSCORE_CRYPTO_AEAD_IV_MAXLEN];

    /** @brief Actual length of the IV/nonce in @ref iv */
    size_t iv_len;

    /** @brief COSE algorithm identifier */
    oscore_crypto_aeadalg_t alg;
} oscore_crypto_aead_encryptstate_t;

/**
 * @brief State of an ongoing AEAD operation
 *
 * Same layout as @ref oscore_crypto_aead_encryptstate_t; kept as a distinct
 * type for parity with libOSCORE's message API.
 */
typedef oscore_crypto_aead_encryptstate_t oscore_crypto_aead_decryptstate_t;

#ifdef __cplusplus
}
#endif
