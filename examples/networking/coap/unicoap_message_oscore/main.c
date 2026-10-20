/*
 * OSCORE variant of the unicoap_message example.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file
 * @brief   Demonstration of OSCORE protection with `unicoap` message APIs
 *
 * This mirrors examples/networking/coap/unicoap_message: a message is created
 * and serialized, and a PDU is parsed and inspected. In addition, the created
 * message is protected with OSCORE before serialization, and the parsed PDU is
 * checked for the OSCORE option and decrypted before its inner content is read.
 *
 * Nothing is sent over a network; the serialized PDU is passed directly to the
 * parsing function.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "net/unicoap.h"

#include <oscore/context_impl/primitive.h>
#include <oscore/message.h>
#include <oscore/protection.h>
#include <oscore_native/message.h>

#include "unicoap_oscore_msg_conversion.h"

#define CLIENT_ID (0x01)
#define SERVER_ID (0x02)

#define OSCORE_OPTION_NUMBER (9)

static const uint8_t master_secret[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
};

static const uint8_t master_salt[8] = {
    0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
};

static struct oscore_context_primitive_immutables _client_immutables;
static struct oscore_context_primitive_immutables _server_immutables;
static struct oscore_context_primitive _client_primitive;
static struct oscore_context_primitive _server_primitive;
static oscore_context_t _client_context;
static oscore_context_t _server_context;

static bool _init_context(struct oscore_context_primitive *primitive,
                          struct oscore_context_primitive_immutables *immutables,
                          oscore_context_t *context,
                          uint8_t sender_id, uint8_t recipient_id,
                          oscore_crypto_hkdfalg_t hkdf_alg)
{
    memset(immutables, 0, sizeof(*immutables));
    immutables->sender_id[0] = sender_id;
    immutables->sender_id_len = 1;
    immutables->recipient_id[0] = recipient_id;
    immutables->recipient_id_len = 1;

    if (oscore_cryptoerr_is_error(
            oscore_crypto_aead_from_number(&immutables->aeadalg, 10 /* AES-CCM-16-64-128 */))) {
        puts("Error: AEAD algorithm not supported");
        return false;
    }

    if (oscore_cryptoerr_is_error(
            oscore_context_primitive_derive(immutables, hkdf_alg,
                                            master_salt, sizeof(master_salt),
                                            master_secret, sizeof(master_secret),
                                            NULL, 0))) {
        puts("Error: could not derive OSCORE security context");
        return false;
    }

    primitive->immutables = immutables;
    context->type = OSCORE_CONTEXT_PRIMITIVE;
    context->data = primitive;
    return true;
}

static bool _example_init_oscore(void)
{
    oscore_crypto_hkdfalg_t hkdf_alg;

    if (oscore_cryptoerr_is_error(
            oscore_crypto_hkdf_from_number(&hkdf_alg, 5 /* HKDF-SHA-256 */))) {
        puts("Error: HKDF algorithm not supported");
        return false;
    }

    return _init_context(&_client_primitive, &_client_immutables, &_client_context,
                         CLIENT_ID, SERVER_ID, hkdf_alg) &&
           _init_context(&_server_primitive, &_server_immutables, &_server_context,
                         SERVER_ID, CLIENT_ID, hkdf_alg);
}

static bool _example_append_option(oscore_msg_protected_t *message,
                                   uint16_t number, const void *value, size_t value_len)
{
    if (oscore_msgerr_protected_is_error(
            oscore_msg_protected_append_option(message, number, value, value_len))) {
        printf("Error: could not append option %u\n", number);
        return false;
    }
    return true;
}

static bool _example_append_string_option(oscore_msg_protected_t *message,
                                          uint16_t number, const char *value)
{
    return _example_append_option(message, number, value, strlen(value));
}

static bool _example_find_oscore_option(oscore_msg_native_t message,
                                        oscore_oscoreoption_t *header)
{
    oscore_msg_native_optiter_t iterator;
    oscore_msg_native_optiter_init(message, &iterator);

    bool found = false;
    uint16_t number;
    const uint8_t *value;
    size_t value_len;

    while (oscore_msg_native_optiter_next(message, &iterator,
                                          &number, &value, &value_len)) {
        if (number == OSCORE_OPTION_NUMBER) {
            found = oscore_oscoreoption_parse(header, value, value_len);
            if (!found) {
                puts("Error: malformed OSCORE option");
            }
            break;
        }
    }

    oscore_msgerr_native_t err = oscore_msg_native_optiter_finish(message, &iterator);
    if (oscore_msgerr_native_is_error(err)) {
        puts("Error: could not iterate over options");
        return false;
    }

    if (!found) {
        puts("Error: message has no OSCORE option");
    }
    return found;
}

static void _example_handle_message(oscore_msg_protected_t *message)
{
    /* The decrypted message is read through the OSCORE protected message API.
     * Its inner options are not visible through the unicoap options API, as
     * those only contain the outer (unprotected) options. */
    oscore_msg_protected_optiter_t iterator;
    oscore_msg_protected_optiter_init(message, &iterator);

    uint16_t number;
    const uint8_t *value;
    size_t value_len;
    uint32_t content_format = 0;

    puts("Inner message options:");
    while (oscore_msg_protected_optiter_next(message, &iterator,
                                             &number, &value, &value_len)) {
        printf("- option %s (%u) contains %u byte(s)\n",
               unicoap_string_from_option_number(number), number, (unsigned)value_len);

        if (number == 12 /* Content-Format */) {
            content_format = 0;
            for (size_t i = 0; i < value_len; i++) {
                content_format = (content_format << 8) | value[i];
            }
        }
    }

    if (oscore_msgerr_protected_is_error(
            oscore_msg_protected_optiter_finish(message, &iterator))) {
        puts("Error: could not iterate over inner options");
        return;
    }

    if (content_format != UNICOAP_FORMAT_JSON) {
        puts("Error: was expecting JSON request!");
        return;
    }

    uint8_t *payload;
    size_t payload_len;
    if (oscore_msgerr_protected_is_error(
            oscore_msg_protected_map_payload(message, &payload, &payload_len))) {
        puts("Error: could not map inner payload");
        return;
    }

    printf("Inner CoAP %s request with payload=<%u bytes>: %.*s\n",
           unicoap_string_from_method(oscore_msg_protected_get_code(message)),
           (unsigned)payload_len, (int)payload_len, (const char *)payload);
}

static ssize_t _example_create_message(uint8_t *pdu, size_t capacity)
{
    /* The options structure only holds the outer options. libOSCORE adds the
     * OSCORE option (number 9) to it automatically. */
    UNICOAP_OPTIONS_ALLOC(options, 100);

    const char text[] = "Dear thermostat, please adjust your target temperature to 22.5 °C";

    /* For a writable OSCORE message, the unicoap payload buffer must provide
     * the full capacity that OSCORE may use for the inner code, options,
     * payload marker, payload, and AEAD tag. */
    uint8_t payload_buffer[256];
    unicoap_message_t message;
    unicoap_request_init_with_options(&message, UNICOAP_METHOD_POST,
                                      payload_buffer, sizeof(payload_buffer),
                                      &options);

    oscore_msg_native_t native = oscore_msg_native_from_unicoap(&message);
    oscore_msg_protected_t protected;
    oscore_requestid_t request_id;

    if (oscore_prepare_request(native, &protected, &_client_context, &request_id) !=
        OSCORE_PREPARE_OK) {
        puts("Error: could not prepare OSCORE request");
        return -1;
    }

    /* Add the same content as in the unicoap_message example, but as inner
     * (encrypted) options. Options must be appended in ascending order. */
    if (!_example_append_string_option(&protected, 11 /* Uri-Path */, "thermostat") ||
        !_example_append_string_option(&protected, 11 /* Uri-Path */, "temperature") ||
        !_example_append_string_option(&protected, 11 /* Uri-Path */, "target")) {
        return -1;
    }

    uint8_t json_format = UNICOAP_FORMAT_JSON;
    if (!_example_append_option(&protected, 12 /* Content-Format */,
                                &json_format, sizeof(json_format))) {
        return -1;
    }

    if (!_example_append_string_option(&protected, 15 /* Uri-Query */, "unit=C") ||
        !_example_append_string_option(&protected, 15 /* Uri-Query */, "cool=yes") ||
        !_example_append_string_option(&protected, 15 /* Uri-Query */, "time=now")) {
        return -1;
    }

    oscore_msg_protected_set_code(&protected, UNICOAP_METHOD_POST);

    uint8_t *inner_payload;
    size_t inner_payload_len;
    if (oscore_msgerr_protected_is_error(
            oscore_msg_protected_map_payload(&protected,
                                             &inner_payload, &inner_payload_len))) {
        puts("Error: could not map inner payload");
        return -1;
    }

    size_t text_len = strlen(text);
    if (text_len > inner_payload_len) {
        puts("Error: payload buffer too small");
        return -1;
    }
    memcpy(inner_payload, text, text_len);

    if (oscore_msgerr_protected_is_error(
            oscore_msg_protected_trim_payload(&protected, text_len))) {
        puts("Error: could not trim inner payload");
        return -1;
    }

    oscore_msg_native_t encrypted;
    if (oscore_encrypt_message(&protected, &encrypted) != OSCORE_FINISH_OK) {
        puts("Error: could not encrypt message");
        return -1;
    }

    unicoap_message_properties_t properties = {
        .token = NULL,
        .token_length = 0,
        .rfc7252 = {
            .id = 0xABCD,
            .type = UNICOAP_TYPE_NON,
        },
    };

    ssize_t result = unicoap_pdu_build_rfc7252(pdu, capacity, &message, &properties);
    if (result < 0) {
        printf("Error: could not serialize message (%s)\n", strerror(-result));
        return result;
    }

    printf("The final OSCORE PDU has a size of %u bytes.\n", (unsigned)result);
    return result;
}

static void _example_parse_pdu(uint8_t *pdu, size_t size)
{
    unicoap_parser_result_t parsed = { 0 };

    if (unicoap_pdu_parse_rfc7252_result(pdu, size, &parsed) < 0) {
        puts("Error: parsing failed");
        return;
    }

    printf("CoAP message has token=<%i bytes>\n", parsed.properties.token_length);
    printf("CoAP over UDP/DTLS has id=%i type=%s\n",
           parsed.properties.rfc7252.id,
           unicoap_string_from_rfc7252_type(parsed.properties.rfc7252.type));

    oscore_msg_native_t native = oscore_msg_native_from_unicoap(&parsed.message);
    oscore_oscoreoption_t header;

    if (!_example_find_oscore_option(native, &header)) {
        return;
    }
    puts("Detected OSCORE option");

    oscore_msg_protected_t unprotected;
    oscore_requestid_t request_id;

    enum oscore_unprotect_request_result result =
        oscore_unprotect_request(native, &unprotected, &header,
                                 &_server_context, &request_id);

    if (result != OSCORE_UNPROTECT_REQUEST_OK &&
        result != OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
        puts("Error: could not decrypt OSCORE message");
        return;
    }

    if (result == OSCORE_UNPROTECT_REQUEST_DUPLICATE) {
        puts("Warning: message is a replay");
    } else {
        puts("Successfully decrypted OSCORE message");
    }

    _example_handle_message(&unprotected);
    oscore_release_unprotected(&unprotected);
}

int main(void)
{
    puts("Initializing OSCORE context ===========");

    if (!_example_init_oscore()) {
        return 1;
    }

    uint8_t pdu[300];

    puts("Creating a sample OSCORE message ============");
    ssize_t pdu_len = _example_create_message(pdu, sizeof(pdu));
    if (pdu_len < 0) {
        return 1;
    }

    puts("Parsing the OSCORE message =================");
    _example_parse_pdu(pdu, pdu_len);
    return 0;
}
