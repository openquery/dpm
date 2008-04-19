/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef _SHA1_H
#define _SHA1_H

#define	SHA1_BLOCK_LENGTH		64
#define	SHA1_DIGEST_LENGTH		20
#define	SHA1_DIGEST_STRING_LENGTH	(SHA1_DIGEST_LENGTH * 2 + 1)

typedef struct {
    u_int32_t state[5];
    u_int64_t count;
    u_int8_t buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *);
void SHA1Pad(SHA1_CTX *);
void SHA1Transform(u_int32_t [5], const u_int8_t [SHA1_BLOCK_LENGTH]);
void SHA1Update(SHA1_CTX *, const u_int8_t *, size_t);
void SHA1Final(u_int8_t [SHA1_DIGEST_LENGTH], SHA1_CTX *);

#endif /* _SHA1_H */
