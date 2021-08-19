#define SIG_FALCON1024_int_SECRETKEYBYTES   2305
#define SIG_FALCON1024_int_PUBLICKEYBYTES   1793
#define SIG_FALCON1024_int_BYTES            1330
#define SIG_FALCON1024_int_ALGNAME          "Falcon-1024"

#ifdef __cplusplus
extern "C" {
#endif

int SIG_FALCON1024_int_sign_keypair(
	unsigned char *pk, unsigned char *sk,
	unsigned char* seed, unsigned long long seedlen);

int SIG_FALCON1024_int_sign_signature(unsigned char *sig, unsigned long long *siglen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);

int SIG_FALCON1024_int_sign_verify(const unsigned char *m, unsigned long long mlen,
	const unsigned char *sig, unsigned long long siglen,
	const unsigned char *pk);

#ifdef __cplusplus
}
#endif
