/*
 * Copyright (c) 2015-2019 Intel Corporation.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "vmm_base.h"

/*
 *  FUNCTION
 *      hkdf_sha256
 *
 *  Description
 *      HMAC-based Extract-and-Expand Key Derivation Function.
 *
 *  Parameters:
 *      out_key     Pointer to key buffer which is used to save
 *                  hkdf_sha256 result
 *      out_len     The length of out_key
 *      secret      Pointer to input keying material
 *      secret_len  The length of secret
 *      salt        Pointer to salt buffer, it is optional
 *                  if not provided (salt == NULL), it is set internally
 *                  to a string of hashlen(32) zeros
 *      salt_len    The length of the salt value
 *                  Ignored if salt is NULL
 *      info        Pointer to application specific information, it is
 *                  optional
 *                  Ignored if info == NULL or a zero-length string
 *      info_len:   The length of the info, ignored if info is NULL
 *
 *  OUTPUTS
 *      1 - Success
 *      0 - Failure
 */

int hkdf_sha256(uint8_t *out_key, uint32_t out_len,
		const uint8_t *secret, uint32_t secret_len,
		const uint8_t *salt, uint32_t salt_len,
		const uint8_t *info, uint32_t info_len);

/**
 * \brief          This function calculates the full generic HMAC
 *                 on the input buffer with the provided key.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The HMAC result is calculated as
 *                 output = generic HMAC(hmac key, input buffer).
 *
 * \param key      The HMAC secret key.
 * \param keylen   The length of the HMAC secret key in Bytes.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The generic HMAC result.
 *
 *      1 - Success
 *      0 - Failure
 */
int hmac_sha256(const uint8_t *key, uint32_t keylen,
		const uint8_t *input, uint32_t ilen,
		uint8_t *output );

#endif  /* _CRYPTO_H_ */
