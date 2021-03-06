/*
 * Wrapper for implementing the NIST API for the PQC standardization
 * process.
 */

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "inner.h"

#include <openssl/rand.h>

#ifndef SIG_FALCON1024_int_DISABLED

#define NONCELEN   40

/*
 * If stack usage is an issue, define TEMPALLOC to static in order to
 * allocate temporaries in the data section instead of the stack. This
 * would make the SIG_FALCON1024_int_sign_keypair(), crypto_sign(), and
 * SIG_FALCON1024_int_sign_open() functions not reentrant and not thread-safe, so
 * this should be done only for testing purposes.
 */
#define TEMPALLOC

int
SIG_FALCON1024_int_sign_keypair(unsigned char *pk, unsigned char *sk, unsigned char *seed, unsigned long long seedlen)
{
	TEMPALLOC union {
		uint8_t b[FALCON_KEYGEN_TEMP_10];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[1024], g[1024], F[1024];
	TEMPALLOC uint16_t h[1024];
	TEMPALLOC inner_shake256_context rng;
	size_t u, v;


	/*
	 * Generate key pair.
	 */
	inner_shake256_init(&rng);
	inner_shake256_inject(&rng, seed, seedlen);
	inner_shake256_flip(&rng);
	Zf(keygen)(&rng, f, g, F, NULL, h, 10, tmp.b);


	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + 10;
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, SIG_FALCON1024_int_SECRETKEYBYTES - u,
		f, 10, Zf(max_fg_bits)[10]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, SIG_FALCON1024_int_SECRETKEYBYTES - u,
		g, 10, Zf(max_fg_bits)[10]);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, SIG_FALCON1024_int_SECRETKEYBYTES - u,
		F, 10, Zf(max_FG_bits)[10]);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != SIG_FALCON1024_int_SECRETKEYBYTES) {
		return -1;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + 10;
	v = Zf(modq_encode)(pk + 1, SIG_FALCON1024_int_PUBLICKEYBYTES - 1, h, 10);
	if (v != SIG_FALCON1024_int_PUBLICKEYBYTES - 1) {
		return -1;
	}

	return 0;
}

int
SIG_FALCON1024_int_sign_signature(unsigned char *sig, unsigned long long *siglen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk)
{
	TEMPALLOC union {
		uint8_t b[72 * 1024];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[1024], g[1024], F[1024], G[1024];
	TEMPALLOC union {
		int16_t sig[1024];
		uint16_t hm[1024];
	} r;
	TEMPALLOC unsigned char seed[48], nonce[NONCELEN];
	TEMPALLOC unsigned char esig[SIG_FALCON1024_int_BYTES - 2 - sizeof nonce];
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len;

	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + 10) {
		return -1;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, 10, Zf(max_fg_bits)[10],
		sk + u, SIG_FALCON1024_int_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, 10, Zf(max_fg_bits)[10],
		sk + u, SIG_FALCON1024_int_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, 10, Zf(max_FG_bits)[10],
		sk + u, SIG_FALCON1024_int_SECRETKEYBYTES - u);
	if (v == 0) {
		return -1;
	}
	u += v;
	if (u != SIG_FALCON1024_int_SECRETKEYBYTES) {
		return -1;
	}
	if (!Zf(complete_private)(G, f, g, F, 10, tmp.b)) {
		return -1;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	RAND_bytes(nonce, sizeof nonce);

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, sizeof nonce);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, 10);

	/*
	 * Initialize a RNG.
	 */
	RAND_bytes(seed, sizeof seed);
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, sizeof seed);
	inner_shake256_flip(&sc);


	/*
	 * Compute the signature.
	 */
	Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, 10, tmp.b);


	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian
	 *   nonce                40 bytes
	 *   message              mlen bytes
	 *   signature            slen bytes
	 */
	esig[0] = 0x20 + 10;
	sig_len = Zf(comp_encode)(esig + 1, (sizeof esig) - 1, r.sig, 10);
	if (sig_len == 0) {
		return -1;
	}
	sig_len ++;
	//memmove(sm + 2 + sizeof nonce, m, mlen);
	//sm[0] = (unsigned char)(sig_len >> 8);
	//sm[1] = (unsigned char)sig_len;
	//memcpy(sm + 2, nonce, sizeof nonce);
	//memcpy(sm + 2 + (sizeof nonce) + mlen, esig, sig_len);
	//*smlen = 2 + (sizeof nonce) + mlen + sig_len;
	memcpy(sig, nonce, sizeof nonce);
	memcpy(sig + (sizeof nonce), esig, sig_len);
	*siglen = (sizeof nonce) + sig_len;
	return 0;
}

int
SIG_FALCON1024_int_sign_verify(const unsigned char *m, unsigned long long mlen,
	const unsigned char *s, unsigned long long slen,
	const unsigned char *pk)
{
	TEMPALLOC union {
		uint8_t b[2 * 1024];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	const unsigned char *esig;
	TEMPALLOC uint16_t h[1024], hm[1024];
	TEMPALLOC int16_t sig[1024];
	TEMPALLOC inner_shake256_context sc;
	size_t sig_len;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 10) {
		return -1;
	}
	if (Zf(modq_decode)(h, 10, pk + 1, SIG_FALCON1024_int_PUBLICKEYBYTES - 1)
		!= SIG_FALCON1024_int_PUBLICKEYBYTES - 1)
	{
		return -1;
	}
	Zf(to_ntt_monty)(h, 10);

	/*
	 * Find nonce, signature, message length.
	 */
	if (slen < NONCELEN) {
		return -1;
	}
	sig_len = slen - NONCELEN;

	/*
	 * Decode signature.
	 */
	esig = s + NONCELEN;
	if (sig_len < 1 || esig[0] != 0x20 + 10) {
		return -1;
	}
	if (Zf(comp_decode)(sig, 10,
		esig + 1, sig_len - 1) != sig_len - 1)
	{
		return -1;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, s, NONCELEN);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, 10);

	/*
	 * Verify signature.
	 */
	if (!Zf(verify_raw)(hm, sig, h, 10, tmp.b)) {
		return -1;
	}

	/*
	 * Return successful.
	 */
	return 0;
}

#endif
