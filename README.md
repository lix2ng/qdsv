# qDSA


This is qDSA, the quotient Digital Signature Algorithm, specifically the Genus-2 variant by Joost Renes. I have modified the original Cortex-M0 code to better support Cortex-M4. Now with Cortex-M3 being added to the list, practically all Cortex-M cores can run at optimized speeds.

It's intended for use in a bootloader for Secure Firmware Update or Secure Boot. Since verifier was my main focus, I named the package "qdsv". The signing and DH routines are still available in the source.

A few words about performance data: they are collected on uVision instruction set simulator, which has some limitations. The cycle numbers are by no means accurate. However if your MCU has code cache (most fast ones do), Flash wait cycles can be ignored if you're counting milli-seconds. M0 and M3 should be pretty close, but M4 and M7 have pipelined long MAC instructions and M7 is dual-issue, you may expect 100-300Kc extra savings.

You'll need arm-none-eabi-gcc to compile. Details are all in the code comments.

This code is in Public Domain without any warranty; please read the LICENSE. Bug fixes, performance reports and improvements are all welcome.

1F2I: Most stones have been turned. This marks the end of the 2021 CNY holiday session.

## The interface

    /*
     * Return 0 if verification passed successfully.
     *
     * NB: arguments are declared as byte arrays for convenience, but they all must
     * be word-aligned. This is OK for bootloader use. You may need to change the
     * source code and use memcpy to handle unaligned input/output buffers.
     */
    int qdsa_verify(const uint8_t sig[64], const uint8_t pk[32], const uint8_t msg[32]);

## The README

    /*
     * Digital Signature Verifier
     *
     * Based on qDSA signature scheme and Cortex-M0 code, by Joost Renes (1),
     * using the hyperelliptic Gaudry-Schost curve (2).
     *
     * Modifications:
     *  - C files are merged and cleaned up.
     *  - assembly files are put together and made EABI compliant.
     *  - add optimized assemblers for Cortex-M4 and Cortex-M3.
     *  - use Bob Jr. as the hash function (reduced round Keccak-f[800]).
     *  - use WAM for fast copy/zeroize/swap on small aligned memory blocks.
     *  - use variable-time Ladder swap in verifier-only compile (saves ~140Kc).
     *  - interfaces are changed for convenience.
     *
     * Limitations:
     *  - message size is fixed to 32 bytes.
     *  - signature, public key and message are required to be word-aligned.
     *
     * Current verifier performance [1f32]:
     *    M0: 5008Kc (104ms on 48MHz M0), 5944B Flash, 752B stack.
     *    M3: 3607Kc (56ms on 64MHz M3),  5104B Flash, 732B stack.
     *    M4: 2876Kc (45ms on 64MHz M4),  4988B Flash, 724B stack.
     *
     * Ref: arm-none-eabi-gcc 7.3.1 20180622 (release). Numbers are obtained on
     * uVision simulator -- which doesn't consider slow Flash wait cycles nor
     * savings from code cache and code/data pipelining.
     *
     * 1. J. Renes, B. Smith: qDSA: Small and Secure Digital Signatures with Curve-
     *    based Diffie-Hellman Key Pairs.
     *    https://arxiv.org/abs/1709.03358
     *    https://joostrenes.nl/software/arm-g2.tar.gz
     * 2. P. Gaudry, E. Schost: Genus 2 point counting over prime fields.
     *    https://www.sciencedirect.com/science/article/pii/S0747717111001386
     */

