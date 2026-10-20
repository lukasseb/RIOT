/*
 * SPDX-FileCopyrightText: 2026 Lukas Sebrantke
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file
 * @ingroup net_unicoap_oscore
 * @brief   libOSCORE native cryptography backend for RIOT
 * @author  Lukas Sebrantke
 *
 * This backend implements the AEAD and HKDF primitives required by libOSCORE
 * using RIOT's noisy primitives:
 *
 * - AEAD: ChaCha20-Poly1305 (RFC 8439) via @ref sys_crypto_chacha20poly1305,
 *         AES-CCM-16-64-128 (RFC 3610) via @ref sys_crypto_modes
 * - KDF:  HKDF-SHA-256 (RFC 5869) via @ref sys_hashes_sha256
 *
 * The corresponding COSE algorithm identifiers are 24 (ChaCha20-Poly1305),
 * 10 (AES-CCM-16-64-128) and 5 (HKDF-SHA-256), matching what libOSCORE requests
 * for these primitives.
 *
 * Per RFC 8613, AES-CCM-16-64-128 (COSE alg 10) is the mandatory-to-implement
 * AEAD; ChaCha20-Poly1305 (COSE alg 24) is supported additionally.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto/ciphers.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/modes/ccm.h"
#include "hashes/sha256.h"

#include <oscore_native/crypto.h>

/** @brief COSE identifier of AES-CCM-16-64-128 (mandatory in RFC 8613) */
#define COSE_ALG_AESCCM_16_64_128 (10)
/** @brief COSE identifier of ChaCha20-Poly1305 */
#define COSE_ALG_CHACHA20POLY1305 (24)
/** @brief COSE identifier of HKDF-SHA-256 */
#define COSE_ALG_HKDF_SHA256 (5)

/** @brief ChaCha20-Poly1305 tag length in bytes */
#define CHACHA20POLY1305_TAGLEN CHACHA20POLY1305_TAG_BYTES
/** @brief AES-CCM-16-64-128 tag length in bytes */
#define AESCCM_TAGLEN (8U)
/** @brief AES-CCM-16-64-128 nonce length in bytes */
#define AESCCM_NONCE_LEN (13U)
/** @brief AES-CCM-16-64-128 key length in bytes */
#define AESCCM_KEY_LEN (16U)
/** @brief Maximum plaintext length encoded in the CCM L field */
#define AESCCM_LENGTH_ENCODING (2U)

static bool _alg_supported(oscore_crypto_aeadalg_t alg)
{
    return alg == COSE_ALG_CHACHA20POLY1305 || alg == COSE_ALG_AESCCM_16_64_128;
}

oscore_cryptoerr_t oscore_crypto_aead_from_number(oscore_crypto_aeadalg_t* alg, int32_t number)
{
    if (!_alg_supported(number)) {
        return true;
    }
    *alg = number;
    return false;
}

oscore_cryptoerr_t oscore_crypto_aead_from_string(oscore_crypto_aeadalg_t* alg, const uint8_t* string,
                                                  size_t string_len)
{
    static const char name_chacha[] = "ChaCha20Poly1305";
    static const char name_aesccm[] = "AES-CCM-16-64-128";

    if (string_len == sizeof(name_chacha) - 1 &&
        memcmp(string, name_chacha, sizeof(name_chacha) - 1) == 0) {
        *alg = COSE_ALG_CHACHA20POLY1305;
        return false;
    }

    if (string_len == sizeof(name_aesccm) - 1 &&
        memcmp(string, name_aesccm, sizeof(name_aesccm) - 1) == 0) {
        *alg = COSE_ALG_AESCCM_16_64_128;
        return false;
    }

    return true;
}

oscore_cryptoerr_t oscore_crypto_aead_get_number(oscore_crypto_aeadalg_t alg, int32_t* number)
{
    if (!_alg_supported(alg)) {
        return true;
    }
    *number = alg;
    return false;
}

oscore_cryptoerr_t oscore_crypto_aead_get_string(oscore_crypto_aeadalg_t alg, const char** string,
                                                 size_t* string_len)
{
    (void)alg;
    (void)string;
    (void)string_len;
    /* Only numeric identifiers are implemented. */
    return true;
}

size_t oscore_crypto_aead_get_taglength(oscore_crypto_aeadalg_t alg)
{
    switch (alg) {
    case COSE_ALG_CHACHA20POLY1305:
        return CHACHA20POLY1305_TAGLEN;
    case COSE_ALG_AESCCM_16_64_128:
        return AESCCM_TAGLEN;
    default:
        return SIZE_MAX;
    }
}

size_t oscore_crypto_aead_get_ivlength(oscore_crypto_aeadalg_t alg)
{
    switch (alg) {
    case COSE_ALG_CHACHA20POLY1305:
        return CHACHA20POLY1305_NONCE_BYTES;
    case COSE_ALG_AESCCM_16_64_128:
        return AESCCM_NONCE_LEN;
    default:
        return SIZE_MAX;
    }
}

size_t oscore_crypto_aead_get_keylength(oscore_crypto_aeadalg_t alg)
{
    switch (alg) {
    case COSE_ALG_CHACHA20POLY1305:
        return CHACHA20POLY1305_KEY_BYTES;
    case COSE_ALG_AESCCM_16_64_128:
        return AESCCM_KEY_LEN;
    default:
        return SIZE_MAX;
    }
}

/**
 * @brief Common setup for encryption and decryption states
 */
static oscore_cryptoerr_t _aead_start(oscore_crypto_aead_encryptstate_t* state,
                                      oscore_crypto_aeadalg_t alg, size_t aad_len,
                                      const uint8_t* iv, const uint8_t* key)
{
    if (!_alg_supported(alg)) {
        return true;
    }

    if (aad_len > OSCORE_CRYPTO_AAD_MAXLEN) {
        return true;
    }

    state->alg = alg;
    state->aad_len = aad_len;
    state->aad_received = 0;

    state->iv_len = oscore_crypto_aead_get_ivlength(alg);
    memcpy(state->iv, iv, state->iv_len);
    memcpy(state->key, key, oscore_crypto_aead_get_keylength(alg));

    return false;
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_start(oscore_crypto_aead_encryptstate_t* state,
                                                    oscore_crypto_aeadalg_t alg, size_t aad_len,
                                                    size_t plaintext_len, const uint8_t* iv,
                                                    const uint8_t* key)
{
    /* The plaintext length is implied by the in-place buffer length at the end
     * of the operation and does not need to be stored. */
    (void)plaintext_len;
    return _aead_start(state, alg, aad_len, iv, key);
}

oscore_cryptoerr_t oscore_crypto_aead_decrypt_start(oscore_crypto_aead_decryptstate_t* state,
                                                    oscore_crypto_aeadalg_t alg, size_t aad_len,
                                                    size_t plaintext_len, const uint8_t* iv,
                                                    const uint8_t* key)
{
    (void)plaintext_len;
    return _aead_start(state, alg, aad_len, iv, key);
}

/**
 * @brief Append an AAD chunk to the buffered AAD
 */
static oscore_cryptoerr_t _aead_feed_aad(oscore_crypto_aead_encryptstate_t* state,
                                         const uint8_t* aad_chunk, size_t aad_chunk_len)
{
    if (aad_chunk_len > (state->aad_len - state->aad_received)) {
        return true;
    }

    if (aad_chunk_len != 0) {
        memcpy(state->aad + state->aad_received, aad_chunk, aad_chunk_len);
        state->aad_received += aad_chunk_len;
    }

    return false;
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_feed_aad(void* state, const uint8_t* aad_chunk,
                                                       size_t aad_chunk_len)
{
    return _aead_feed_aad((oscore_crypto_aead_encryptstate_t*)state, aad_chunk, aad_chunk_len);
}

oscore_cryptoerr_t oscore_crypto_aead_decrypt_feed_aad(void* state, const uint8_t* aad_chunk,
                                                       size_t aad_chunk_len)
{
    return _aead_feed_aad((oscore_crypto_aead_decryptstate_t*)state, aad_chunk, aad_chunk_len);
}

oscore_cryptoerr_t oscore_crypto_aead_encrypt_inplace(oscore_crypto_aead_encryptstate_t* state,
                                                      uint8_t* buffer, size_t buffer_len)
{
    if (state->aad_received != state->aad_len) {
        return true;
    }

    size_t tag_len = oscore_crypto_aead_get_taglength(state->alg);
    if (buffer_len < tag_len) {
        return true;
    }

    size_t plaintext_len = buffer_len - tag_len;

    switch (state->alg) {
    case COSE_ALG_CHACHA20POLY1305:
        /* chacha20poly1305_encrypt writes the tag right after the ciphertext,
         * which fits exactly into the provided buffer. In-place operation is
         * supported. */
        chacha20poly1305_encrypt(buffer, buffer, plaintext_len, state->aad, state->aad_len,
                                 state->key, state->iv);
        return false;

    case COSE_ALG_AESCCM_16_64_128: {
        cipher_t cipher;
        if (cipher_init(&cipher, CIPHER_AES, state->key, AESCCM_KEY_LEN) < 0) {
            return true;
        }
        int res = cipher_encrypt_ccm(&cipher, state->aad, state->aad_len, AESCCM_TAGLEN,
                                     AESCCM_LENGTH_ENCODING, state->iv, state->iv_len,
                                     buffer, plaintext_len, buffer);
        return res < 0;
    }

    default:
        return true;
    }
}

oscore_cryptoerr_t oscore_crypto_aead_decrypt_inplace(oscore_crypto_aead_decryptstate_t* state,
                                                      uint8_t* buffer, size_t buffer_len)
{
    if (state->aad_received != state->aad_len) {
        return true;
    }

    size_t tag_len = oscore_crypto_aead_get_taglength(state->alg);
    if (buffer_len < tag_len) {
        return true;
    }

    size_t plaintext_len = buffer_len - tag_len;

    switch (state->alg) {
    case COSE_ALG_CHACHA20POLY1305: {
        size_t result_len = plaintext_len;
        int res = chacha20poly1305_decrypt(buffer, buffer_len, buffer, &result_len, state->aad,
                                           state->aad_len, state->key, state->iv);
        return !(res == 1 && result_len == plaintext_len);
    }

    case COSE_ALG_AESCCM_16_64_128: {
        cipher_t cipher;
        if (cipher_init(&cipher, CIPHER_AES, state->key, AESCCM_KEY_LEN) < 0) {
            return true;
        }
        int res = cipher_decrypt_ccm(&cipher, state->aad, state->aad_len, AESCCM_TAGLEN,
                                     AESCCM_LENGTH_ENCODING, state->iv, state->iv_len,
                                     buffer, buffer_len, buffer);
        return !(res >= 0 && (size_t)res == plaintext_len);
    }

    default:
        return true;
    }
}

/* MARK: - HKDF */

oscore_cryptoerr_t oscore_crypto_hkdf_from_number(oscore_crypto_hkdfalg_t* alg, int32_t number)
{
    if (number != COSE_ALG_HKDF_SHA256) {
        return true;
    }
    *alg = COSE_ALG_HKDF_SHA256;
    return false;
}

oscore_cryptoerr_t oscore_crypto_hkdf_from_string(oscore_crypto_hkdfalg_t* alg, uint8_t* string,
                                                  size_t string_len)
{
    static const char name[] = "HKDF-SHA-256";
    if (string_len == sizeof(name) - 1 && memcmp(string, name, sizeof(name) - 1) == 0) {
        *alg = COSE_ALG_HKDF_SHA256;
        return false;
    }
    return true;
}

oscore_cryptoerr_t oscore_crypto_hkdf_derive(oscore_crypto_hkdfalg_t alg, const uint8_t* salt,
                                             size_t salt_len, const uint8_t* ikm, size_t ikm_len,
                                             const uint8_t* info, size_t info_len, uint8_t* out,
                                             size_t out_len)
{
    if (alg != COSE_ALG_HKDF_SHA256) {
        return true;
    }

    /* RFC 5869 caps the output at 255 * HashLen bytes. */
    if (out_len > 255U * SHA256_DIGEST_LENGTH) {
        return true;
    }

    /* HKDF-Extract: PRK = HMAC-Hash(salt, IKM) */
    static const uint8_t zero_salt[SHA256_DIGEST_LENGTH] = { 0 };
    if (salt_len == 0) {
        /* RFC 5869: absent salt is a string of HashLen zeros. */
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    uint8_t prk[SHA256_DIGEST_LENGTH];
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* HKDF-Expand: T(i) = HMAC-Hash(PRK, T(i-1) | info | i) */
    uint8_t t[SHA256_DIGEST_LENGTH];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        hmac_context_t ctx;
        hmac_sha256_init(&ctx, prk, sizeof(prk));

        if (t_len != 0) {
            hmac_sha256_update(&ctx, t, t_len);
        }
        if (info_len != 0) {
            hmac_sha256_update(&ctx, info, info_len);
        }
        hmac_sha256_update(&ctx, &counter, 1);
        hmac_sha256_final(&ctx, t);

        t_len = sizeof(t);
        size_t copy = out_len - done;
        if (copy > t_len) {
            copy = t_len;
        }
        memcpy(out + done, t, copy);
        done += copy;
        counter += 1;
    }

    /* Wipe intermediate key material. */
    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));

    return false;
}

bool oscore_cryptoerr_is_error(oscore_cryptoerr_t err)
{
    return err;
}
