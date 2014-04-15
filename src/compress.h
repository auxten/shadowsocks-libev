/*
 * compress.h
 *
 *  Created on: 2014��4��1��
 *      Author: auxten
 */

#ifndef COMPRESS_H_
#define COMPRESS_H_


char* ss_decompress(int inbuf_size, char *ciphertext, ssize_t *len, struct enc_ctx *ctx);
char* ss_compress(int buf_size, char *plaintext, ssize_t *len, struct enc_ctx *ctx);



#endif /* COMPRESS_H_ */
