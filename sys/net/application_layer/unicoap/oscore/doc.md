@defgroup net_unicoap_oscore unicoap OSCORE Module
@ingroup  net_unicoap
@brief    Object Security for Constrained RESTful Environments (OSCORE) support for unicoap
@{

## Introduction

[OSCORE](https://datatracker.ietf.org/doc/html/rfc8613) provides end-to-end
protection of CoAP messages using COSE. This module adds OSCORE support to
`unicoap` by integrating the
[libOSCORE](https://gitlab.com/oscore/liboscore) library.

Add the module to your application Makefile:

```makefile
USEMODULE += unicoap_oscore
```

This pulls in `unicoap`, libOSCORE, and the cryptographic primitives used by the
RIOT backend. The native backend for `unicoap` messages and the cryptographic
backend are provided by this module and satisfy libOSCORE's
@ref oscore_native_msg and @ref oscore_native_crypto interfaces.

## Architecture

libOSCORE is integrated at the message (de)serializer boundary, following the
struct-based integration guidance. The module provides:

- `oscore_native/msg_type.h`: native message types mapping libOSCORE's
  operations onto @ref unicoap_message_t and its options API.
- `oscore_native/crypto_type.h`: native cryptography types and state.
- `oscore_native/platform.h`: libc-backed platform functions.
- `message.c`: the native message backend.
- `crypto.c`: the cryptographic backend.
- `unicoap_oscore_msg_conversion.h`: helpers to wrap a @ref unicoap_message_t
  into a @ref oscore_msg_native_t and back.

## Cryptography

The cryptographic backend implements the primitives required by OSCORE on top
of RIOT's own implementations:

| Primitive          | COSE identifier | RIOT module                      |
| ------------------ | --------------- | -------------------------------- |
| AES-CCM-16-64-128  | 10              | @ref sys_crypto_modes (cipher_modes) |
| ChaCha20-Poly1305  | 24              | @ref sys_crypto_chacha20poly1305 |
| HKDF-SHA-256       | 5               | @ref sys_hashes_sha256           |

RFC 8613 mandates AES-CCM-16-64-128; ChaCha20-Poly1305 is provided as a second
AEAD option.

## Usage

Because OSCORE operates on an encrypted inner message, an application creates a
@ref unicoap_message_t as usual, then wraps it into a native message handle with
@ref oscore_msg_native_from_unicoap to protect or unprotect it. A complete
example is available in
`examples/networking/coap/unicoap_message_oscore`.

@}
