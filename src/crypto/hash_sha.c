/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <assert.h>
#include <openssl/evp.h>

#include <internal.h>

typedef struct {
    struct NoiseHashState_s parent;
    const EVP_MD           *md;
    EVP_MD_CTX             *ctx;
} NoiseHashState_ex;

static void noise_sha_reset(NoiseHashState *state) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    EVP_DigestInit(st->ctx, st->md);
}

static void noise_sha_update(NoiseHashState *state, const uint8_t *data, size_t len) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    EVP_DigestUpdate(st->ctx, data, len);
}

static void noise_sha_finalize(NoiseHashState *state, uint8_t *hash) {
    NoiseHashState_ex *st = (NoiseHashState_ex *) state;
    EVP_DigestFinal(st->ctx, hash, NULL);
}

static void noise_sha_destroy(NoiseHashState *state) {
    EVP_MD_CTX_free(((NoiseHashState_ex *) state)->ctx);
}

NoiseHashState *noise_sha_new(uint16_t type) {
    NoiseHashState_ex *st = noise_new(NoiseHashState_ex);
    if (!st)
        return NULL;
    st->parent.hash_id = type;
    st->md             = NULL;
    switch (st->parent.hash_id) {
        case NOISE_HASH_SHA256:
            st->md = EVP_sha256();
        case NOISE_HASH_SHA3256:
            if (!st->md)
                st->md = EVP_sha3_256();
            st->parent.hash_len  = 32;
            st->parent.block_len = 64;
            break;
        case NOISE_HASH_SHA512:
            st->md = EVP_sha512();
        case NOISE_HASH_SHA3512:
            if (!st->md)
                st->md = EVP_sha3_512();
            st->parent.hash_len  = 64;
            st->parent.block_len = 128;
            break;
        default:
            return NULL;
    };
    st->ctx = EVP_MD_CTX_new();

    st->parent.destroy  = noise_sha_destroy;
    st->parent.reset    = noise_sha_reset;
    st->parent.update   = noise_sha_update;
    st->parent.finalize = noise_sha_finalize;
    return &(st->parent);
}
