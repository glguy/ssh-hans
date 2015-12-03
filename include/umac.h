/* -----------------------------------------------------------------------
 *
 * umac.h -- C Implementation UMAC Message Authentication
 *
 * Version 0.90 of draft-krovetz-umac-03.txt -- 2004 October
 *
 * For a full description of UMAC message authentication see the UMAC
 * world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
 * Please report bugs and suggestions to the UMAC webpage.
 *
 * Copyright (c) 1999-2004 Ted Krovetz
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and with or without fee, is hereby
 * granted provided that the above copyright notice appears in all copies
 * and in supporting documentation, and that the name of the copyright
 * holder not be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior permission.
 *
 * Comments should be directed to Ted Krovetz (tdk@acm.org)
 *
 * ---------------------------------------------------------------------- */

 /* ////////////////////// IMPORTANT NOTES /////////////////////////////////
  *
  * 1) This version does not work properly on messages larger than 16MB
  *
  * 2) If you set the switch to use SSE2, then all data must be 16-byte
  *    aligned
  *
  * 3) When calling the function umac(), it is assumed that msg is in
  * a writable buffer of length divisible by 32 bytes. The message itself
  * does not have to fill the entire buffer, but bytes beyond msg may be
  * zeroed.
  *
  * 4) Two free AES implementations are supported by this implementation of
  * UMAC. Paulo Barreto's version is in the public domain and can be found
  * at http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ (search for
  * "Barreto"). The only two files needed are rijndael-alg-fst.c and
  * rijndael-alg-fst.h.
  * Brian Gladman's version is distributed with GNU Public lisence
  * and can be found at http://fp.gladman.plus.com/AES/index.htm. It
  * includes a fast IA-32 assembly version.
  *
  /////////////////////////////////////////////////////////////////////// */


#ifdef __cplusplus
    extern "C" {
#endif

typedef struct umac_ctx *umac_ctx_t;

umac_ctx_t umac64_new(char key[]);
void umac64_reset(umac_ctx_t ctx);
void umac64_update(umac_ctx_t ctx, const char *input, long len);
void umac64_final(umac_ctx_t ctx, char tag[], const char nonce[8]);
void umac_delete(umac_ctx_t ctx);

umac_ctx_t umac128_new(const char key[]);
void umac128_update(umac_ctx_t ctx, const char *input, long len);
void umac128_final(umac_ctx_t ctx, char tag[], const char nonce[8]);
void umac128_reset(umac_ctx_t ctx);

typedef struct uhash_ctx *uhash_ctx_t;
static void uhash_reset(uhash_ctx_t);
static void uhash_update(uhash_ctx_t, const char *, long);
static void uhash_final(uhash_ctx_t, char ouput[]);

/* Copied from cryptonite temporarily until incorporation */
/* Copied from cryptonite temporarily until incorporation */
/* Copied from cryptonite temporarily until incorporation */
typedef struct {
	unsigned char nbr; /* number of rounds: 10 (128), 12 (192), 14 (256) */
	unsigned char strength; /* 128 = 0, 192 = 1, 256 = 2 */
	unsigned char _padding[6];
	unsigned char data[16*14*2];
} cryptonite_aes_key;
void cryptonite_aes_encrypt_ecb(void*,const void*,const void*,unsigned int);
void cryptonite_aes_initkey(void*,const void*,unsigned char);
/* Copied from cryptonite temporarily until incorporation */
/* Copied from cryptonite temporarily until incorporation */
/* Copied from cryptonite temporarily until incorporation */

#ifdef __cplusplus
    }
#endif
