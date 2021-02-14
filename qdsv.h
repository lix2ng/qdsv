/*
 * Digital Signature Verifier
 *
 * Based on qDSA signature scheme and Cortex-M0 code, by Joost Renes,
 * using the hyperelliptic Gaudry-Schost curve.
 */

#ifndef QDSV_H_
#define QDSV_H_

/* Lengths are in bytes, all fixed. */
#define QDSA_SIG_LEN 64
#define QDSA_PK_LEN 32
#define QDSA_MSG_LEN 32

/*
 * Return 0 if verification passed successfully.
 *
 * NB: arguments are declared as byte arrays for convenience, but they all must
 * be word-aligned. This is OK for bootloader use. You may need to change the
 * source code and use memcpy to handle unaligned input/output buffers.
 */
int qdsa_verify(
   const uint8_t sig[64], const uint8_t pk[32], const uint8_t msg[32]);

/*
 * Following are optional; see CONF_QDSA_FULL in C.
 */
int qdsa_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);
int qdsa_sign(uint8_t sig[64], const uint8_t msg[32], const uint8_t pk[32],
   const uint8_t sk[64]);
int qdsa_dh_keygen(uint8_t pk[32], const uint8_t sk[32]);
int qdsa_dh_exchange(
   uint8_t ss[32], const uint8_t pk[32], const uint8_t sk[32]);

#endif /* QDSV_H_ */

/* vim: set syn=c cin et sw=3 ts=3 tw=80 fo=cjMmnoqr: */
