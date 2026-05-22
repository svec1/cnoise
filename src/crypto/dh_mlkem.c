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
#include <openssl/mlkem.h>
#include <string.h>

#define MLKEM_SHARED_SECRET_KEY_LEN 32

typedef struct NoiseMlkemState_s {
    struct NoiseDHState_s parent;
    MLKEM_private_key* private_key;
    MLKEM_public_key* public_key;
} NoiseMlkemState;

static void noise_free_keys(NoiseMlkemState* st);
static void noise_allocate_keys(NoiseMlkemState* st) {
    if (st->parent.private_key || st->parent.public_key) noise_free_keys(st);

    st->parent.private_key = malloc(st->parent.private_key_len);
    st->parent.public_key = malloc(st->parent.public_key_len);
    memset(st->parent.private_key, 0, st->parent.private_key_len);
    memset(st->parent.public_key, 0, st->parent.public_key_len);
}
void noise_free_keys(NoiseMlkemState* st) {
    if (st->parent.private_key) {
	free(st->parent.private_key);
	st->parent.private_key = NULL;
    }
    if (st->parent.public_key) {
	free(st->parent.public_key);
	st->parent.public_key = NULL;
    }
}

static int noise_mlkem_generate_keypair(NoiseDHState* state,
					const NoiseDHState* other) {
    NoiseMlkemState* st = (NoiseMlkemState*)state;
    NoiseMlkemState* os = (NoiseMlkemState*)other;

    noise_free_keys(st);

    if (st->parent.role == NOISE_ROLE_RESPONDER) {
	/* Generating the keypair for Bob relative to Alice's parameters */
	if (!os || os->parent.key_type == NOISE_KEY_TYPE_NO_KEY)
	    return NOISE_ERROR_INVALID_STATE;

	// Generate shared secret key to st->parent.private_key
	if (!MLKEM_encap(os->public_key, &st->parent.public_key,
			 &st->parent.public_key_len, &st->parent.private_key,
			 &st->parent.shared_secret_key_len))
	    return NOISE_ERROR_INVALID_STATE;

    } else {
	/* Generate the keypair for Alice */
	if (!MLKEM_generate_key(st->private_key, &st->parent.public_key,
				&st->parent.public_key_len, NULL, NULL) ||
	    !MLKEM_marshal_private_key(st->private_key, &st->parent.private_key,
				       &st->parent.private_key_len) ||
	    !MLKEM_parse_public_key(st->public_key, st->parent.public_key,
				    st->parent.public_key_len))
	    return NOISE_ERROR_INVALID_STATE;
    }

    return NOISE_ERROR_NONE;
}

static int noise_mlkem_set_keypair_private(NoiseDHState* state,
					   const uint8_t* private_key) {
    NoiseMlkemState* st = (NoiseMlkemState*)state;

    if (st->parent.role == NOISE_ROLE_INITIATOR) {
	noise_free_keys(st);
	if (!MLKEM_parse_private_key(st->private_key, private_key,
				     st->parent.private_key_len) ||
	    !MLKEM_public_from_private(st->private_key, st->public_key) ||
	    !MLKEM_marshal_private_key(st->private_key, &st->parent.private_key,
				       &st->parent.private_key_len) ||
	    !MLKEM_marshal_public_key(st->public_key, &st->parent.public_key,
				      &st->parent.public_key_len))
	    return NOISE_ERROR_INVALID_STATE;

    } else {
	/* For RESPONDER: private_key is just the precomputed shared secret (32
	   bytes). The mlkem_pub field (ciphertext) will be set separately via
	   set_keypair. */
	memcpy(st->parent.private_key, private_key,
	       st->parent.shared_secret_key_len);
    }
    return NOISE_ERROR_NONE;
}

static int noise_mlkem_set_keypair(NoiseDHState* st, const uint8_t* private_key,
				   const uint8_t* public_key) {
    /* Ignore the public key and re-generate from the private key */
    return noise_mlkem_set_keypair_private(st, private_key);
}

static int noise_mlkem_validate_public_key(const NoiseDHState* state,
					   const uint8_t* public_key) {
    NoiseMlkemState* st = (NoiseMlkemState*)state;
    return MLKEM_parse_public_key(st->public_key, public_key,
				  st->parent.public_key_len)
	       ? NOISE_ERROR_NONE
	       : NOISE_ERROR_INVALID_STATE;
}

static int noise_mlkem_copy(NoiseDHState* st, const NoiseDHState* from,
			    const NoiseDHState* other) {
    return NOISE_ERROR_NOT_IMPLEMENTED;
}

static int noise_mlkem_calculate(const NoiseDHState* private_key_st,
				 const NoiseDHState* public_key_st,
				 uint8_t* shared_secret_key) {
    NoiseMlkemState* priv_st = (NoiseMlkemState*)private_key_st;
    NoiseMlkemState* pub_st = (NoiseMlkemState*)public_key_st;
    if (priv_st->parent.role == NOISE_ROLE_RESPONDER) {
	/* We already generated the shared secret for Bob when we
	 * generated the "keypair" for him. */
	memcpy(shared_secret_key, priv_st->parent.private_key,
	       priv_st->parent.private_key_len);

    } else {
	uint8_t* shared_secret_key_tmp = NULL;
	size_t shared_secret_key_tmp_len;
	/* Generate the shared secret for Alice */
	if (!MLKEM_decap(priv_st->private_key, pub_st->parent.public_key,
			 pub_st->parent.public_key_len, &shared_secret_key_tmp,
			 &shared_secret_key_tmp_len))
	    return NOISE_ERROR_INVALID_STATE;

	memcpy(shared_secret_key, shared_secret_key_tmp,
	       shared_secret_key_tmp_len);
	free(shared_secret_key_tmp);
    }
    return NOISE_ERROR_NONE;
}

static void noise_mlkem_change_role(NoiseDHState* state) {
    NoiseMlkemState* st = (NoiseMlkemState*)state;

    noise_free_keys(st);

    /* Change the size of the keys based on the object's role */
    if (st->parent.role == NOISE_ROLE_RESPONDER) {
	st->parent.private_key_len = st->parent.shared_secret_key_len;
	st->parent.public_key_len = st->parent.cipher_text_len;
    } else {
	st->parent.private_key_len =
	    MLKEM_private_key_encoded_length(st->private_key);
	st->parent.public_key_len =
	    MLKEM_public_key_encoded_length(st->public_key);
    }

    noise_allocate_keys(st);
}

static void noise_mlkem_destroy(NoiseDHState* state) {
    NoiseMlkemState* st = (NoiseMlkemState*)state;
    MLKEM_private_key_free(((NoiseMlkemState*)st)->private_key);
    MLKEM_public_key_free(((NoiseMlkemState*)st)->public_key);
    noise_free_keys(st);
}

NoiseDHState* noise_mlkem_new(uint16_t type) {
    NoiseMlkemState* st = noise_new(NoiseMlkemState);
    if (!st) return NULL;

    int rank;

    switch (type) {
	case NOISE_DH_MLKEM768:
	    rank = MLKEM768_RANK;
	    break;
	case NOISE_DH_MLKEM1024:
	    rank = MLKEM1024_RANK;
	    break;
	default:
	    return NULL;
    }

    st->private_key = MLKEM_private_key_new(rank);
    st->public_key = MLKEM_public_key_new(rank);
    st->parent.private_key = NULL;
    st->parent.public_key = NULL;

    noise_allocate_keys(st);

    st->parent.dh_id = type;
    st->parent.ephemeral_only = 1;
    st->parent.nulls_allowed = 0;
    st->parent.private_key_len =
	MLKEM_private_key_encoded_length(st->private_key);
    st->parent.public_key_len = MLKEM_public_key_encoded_length(st->public_key);
    st->parent.cipher_text_len =
	MLKEM_private_key_ciphertext_length(st->private_key);
    st->parent.shared_secret_key_len = MLKEM_SHARED_SECRET_KEY_LEN;
    st->parent.generate_keypair = noise_mlkem_generate_keypair;
    st->parent.set_keypair = noise_mlkem_set_keypair;
    st->parent.set_keypair_private = noise_mlkem_set_keypair_private;
    st->parent.validate_public_key = noise_mlkem_validate_public_key;
    st->parent.copy = noise_mlkem_copy;
    st->parent.calculate = noise_mlkem_calculate;
    st->parent.change_role = noise_mlkem_change_role;
    st->parent.destroy = noise_mlkem_destroy;
    NoiseDHState* out = &(st->parent);
    return out;
}
