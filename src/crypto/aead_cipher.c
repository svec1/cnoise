/*
 * Copyright (C) 2026 svec, Pty Ltd.
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

#include <internal.h>
#include <openssl/evp.h>
#include <string.h>

typedef struct {
    struct NoiseCipherState_s parent;
    EVP_AEAD_CTX* ctx;
    const EVP_AEAD* aead;
} NoiseCipherState_ex;

static void noise_aead_cipher_init_key(NoiseCipherState* state,
				       const uint8_t* key) {
    NoiseCipherState_ex* st = (NoiseCipherState_ex*)state;
    EVP_AEAD_CTX_cleanup(st->ctx);
    EVP_AEAD_CTX_init(st->ctx, st->aead, key, st->parent.key_len,
		      st->parent.mac_len, NULL);
}

static int noise_aead_cipher_encrypt(NoiseCipherState* state, const uint8_t* ad,
				     size_t ad_len, uint8_t* data, size_t len) {
    NoiseCipherState_ex* st = (NoiseCipherState_ex*)state;

    if (!EVP_AEAD_CTX_seal(st->ctx, data, &len, len + st->parent.mac_len,
			   st->parent.n, st->parent.n_len, data, len, ad,
			   ad_len))
	return NOISE_ERROR_INVALID_LENGTH;

    return NOISE_ERROR_NONE;
}

static int noise_aead_cipher_decrypt(NoiseCipherState* state, const uint8_t* ad,
				     size_t ad_len, uint8_t* data, size_t len) {
    NoiseCipherState_ex* st = (NoiseCipherState_ex*)state;

    if (!EVP_AEAD_CTX_open(st->ctx, data, &len, len + st->parent.mac_len,
			   st->parent.n, st->parent.n_len, data,
			   len + st->parent.mac_len, ad, ad_len))
	return NOISE_ERROR_MAC_FAILURE;

    return NOISE_ERROR_NONE;
}

static void noise_aead_cipher_destroy(NoiseCipherState* state) {
    EVP_AEAD_CTX_free(((NoiseCipherState_ex*)state)->ctx);
}

NoiseCipherState* noise_aead_cipher_new(uint16_t type) {
    NoiseCipherState_ex* st = noise_new(NoiseCipherState_ex);
    if (!st) return NULL;

    switch (type) {
	case NOISE_CIPHER_AESGCM:
	    st->aead = EVP_aead_aes_256_gcm();
	    break;
	case NOISE_CIPHER_CHACHAPOLY:
	    st->aead = EVP_aead_chacha20_poly1305();
	    break;
	case NOISE_CIPHER_XCHACHAPOLY:
	    st->aead = EVP_aead_xchacha20_poly1305();
	    break;
	default:
	    return NULL;
    }
    st->ctx = EVP_AEAD_CTX_new();

    st->parent.cipher_id = type;
    st->parent.key_len = EVP_AEAD_key_length(st->aead);
    st->parent.mac_len = EVP_AEAD_max_tag_len(st->aead);
    st->parent.n_len = EVP_AEAD_nonce_length(st->aead);
    st->parent.create = noise_aead_cipher_new;
    st->parent.destroy = noise_aead_cipher_destroy;
    st->parent.init_key = noise_aead_cipher_init_key;
    st->parent.encrypt = noise_aead_cipher_encrypt;
    st->parent.decrypt = noise_aead_cipher_decrypt;

    return &(st->parent);
}
