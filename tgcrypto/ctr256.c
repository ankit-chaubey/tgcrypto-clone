/*
 * Pyrogram - Telegram MTProto API Client Library for Python
 * Copyright (C) 2017-present Dan <https://github.com/delivrance>
 *
 * This file is part of Pyrogram.
 *
 * Pyrogram is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pyrogram is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "aes256.h"
#include <stdlib.h>
#include <string.h>

uint8_t *ctr256(const uint8_t in[], uint32_t length, const uint8_t key[32], uint8_t iv[16], uint8_t *state) {
    if (!in || !key || !iv || !state) return NULL;

    uint8_t *out = (uint8_t *) malloc(length);
    if (!out) return NULL;

    uint8_t chunk[AES_BLOCK_SIZE];
    uint32_t expandedKey[EXPANDED_KEY_SIZE];
    uint32_t i, j;

    memcpy(out, in, length);
    aes256_set_encryption_key(key, expandedKey);
    aes256_encrypt(iv, chunk, expandedKey);

    for (i = 0; i < length; i += AES_BLOCK_SIZE) {
        uint32_t blockSize = length - i < AES_BLOCK_SIZE ? length - i : AES_BLOCK_SIZE;

        for (j = 0; j < blockSize; ++j) {
            out[i + j] ^= chunk[*state];
            (*state)++;

            if (*state == AES_BLOCK_SIZE) {
                *state = 0;

                for (int k = AES_BLOCK_SIZE - 1; k >= 0; --k) {
                    if (++iv[k]) break;
                }

                aes256_encrypt(iv, chunk, expandedKey);
            }
        }
    }

    return out;
}
