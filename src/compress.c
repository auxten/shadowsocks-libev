/*
 * compress.c
 *
 *  Created on: 2014Äê4ÔÂ1ÈÕ
 *      Author: auxten
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/md5.h>
#include <openssl/rand.h>

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/md5.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#endif

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#include "encrypt.h"
//#include "utils.h"


//#include "miniz.c"
#include "android_utils.h"
#include <zlib.h>

//#define PLAIN_DEBUG

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint;
static const int COMPRESS_LEVEL = 6;
extern uint8_t *enc_table;
extern uint8_t *dec_table;


void hexdump(void *_data, unsigned len)
{
	if (!_data || len == 0)
	{
		return;
	}
//    const int DIVIDER = DUMP_LINE_WIDTH / 2;
    const int buf_len = len * 2 + 4;
    char * buf = (char *)calloc(buf_len, 1);
    char * bufx = (char *)calloc(buf_len, 1);
    unsigned char *data = _data;
    unsigned count;

    for (count = 0; count < len; data++, count++) {
        snprintf(bufx + count * 2, buf_len - count * 2, "%02x", *data);
//        if (*data)
        snprintf(buf + count * 2, buf_len - count * 2, " %c", (*data < 32) || (*data > 126) ? ' ' : *data);

//        LOGD(" %02x %c", *data,
//                (*data < 32) || (*data > 126) ? '.' : *data);
    }
    {
        LOGD("%s", bufx);
        LOGD("%s", buf);
    }
    free(buf);
    free(bufx);
}

//#define hexdump(a, b)

char* ss_decompress(int inbuf_size, char *ciphertext, ssize_t *len, struct enc_ctx *ctx)
{
	if (ctx != NULL)
	{
#ifndef PLAIN_DEBUG
		LOGD("len %ld\n", *len);
		char * ret = NULL;
		z_stream stream;
		int status;
		uint8 * s_outbuf = NULL;
		ssize_t avail_in;
		ssize_t orig_in_len;
		ssize_t used_in = 0;
		ssize_t used_out = 0;
		ssize_t avail_out;
		int out_buf_size;

		if (!len || *len <= 0)
		{
			goto END;
		}

		avail_out = out_buf_size = MAX(*len * 2, inbuf_size);
		orig_in_len = avail_in = *len;
		s_outbuf = (uint8 *)malloc(out_buf_size);

		hexdump(ciphertext, avail_in);

		while (avail_in)
		{
			// Init the z_stream
			memset(&stream, 0, sizeof(stream));
			if (inflateInit(&stream))
			{
				LOGE("inflateInit() failed!\n");
				goto END;
			}

			stream.next_in = (uint8 *)ciphertext + used_in;
			stream.avail_in = avail_in;
			stream.next_out = s_outbuf + used_out;
			stream.avail_out = avail_out;

			// Decompression.
			for (;;) {
				LOGD("avail_in %d\n", stream.avail_in);

				used_out = out_buf_size - stream.avail_out;
				if (stream.avail_out == 0) {
					stream.avail_out += out_buf_size;
					avail_out = stream.avail_out;
					s_outbuf = (uint8 *) realloc(s_outbuf, out_buf_size * 2);
					stream.next_out = s_outbuf + used_out;
					LOGD("oued_out %ld\n", used_out);
					out_buf_size *= 2;
				}

				status = inflate(&stream, Z_SYNC_FLUSH);
				LOGD("n: %ld, status %d\n", used_out, status);

				if (status == Z_STREAM_END) {
					// Output buffer is full, or decompression is done, so write buffer to output file.
					ret = (char *)s_outbuf;
					LOGD("stream.avail_in %u", stream.avail_in);
					avail_out = stream.avail_out;
					avail_in = stream.avail_in;
					used_in = orig_in_len - avail_in;
					used_out = out_buf_size - avail_out;
					*len = used_out;
				}


				if (status == Z_STREAM_END)
					break;
				else if (status != Z_OK) {
					LOGE("inflate() failed with status %i!\n", status);
					ret = NULL;
					goto END;
				}
			}

			if (inflateEnd(&stream) != Z_OK) {
				LOGE("inflateEnd() failed!\n");
				ret = NULL;
				goto END;
			}

		}
END:
		if (s_outbuf)
			hexdump(s_outbuf, out_buf_size - stream.avail_out);
		if (ret == NULL)
		{
			SAFE_FREE(s_outbuf);
		}

		SAFE_FREE(ciphertext);
		return ret;
#else
		hexdump(ciphertext, *len);
		return ciphertext;
#endif // PLAIN_DEBUG
	}
	else
	{
        char *begin = ciphertext;
        while (ciphertext < begin + *len)
        {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
	}
}

//char* ss_decompress(int inbuf_size, char *ciphertext, ssize_t *len, struct enc_ctx *ctx)
//{
//	char * ret = NULL;
//	ssize_t avail_in = *len;
//
//	while(avail_in)
//	{
//		ret = _ss_decompress(ciphertext + (*len - avail_in), len, &avail_in, ctx);
//		if (ret != NULL)
//		{
//		}
//	}
//}


/**
 * remember to free the returned buf
 */
char* ss_compress(int buf_size, char *plaintext, ssize_t *len, struct enc_ctx *ctx)
{
//	__android_log_print(ANDROID_LOG_DEBUG, "socks-compress", "ddddddddddddddddddddddddddddddddd");
	if (ctx != NULL)
    {

#ifndef PLAIN_DEBUG
		char * ret = NULL;
		if (!len || *len <= 0)
		{
			SAFE_FREE(plaintext);
			return ret;
		}

		hexdump(plaintext, *len);

		unsigned long cmp_len = MAX(buf_size, compressBound(*len));
		unsigned char * pCmp = (unsigned char *)calloc(cmp_len, 1);

		int cmp_status = compress2(pCmp, &cmp_len, (const unsigned char *) plaintext, *len, COMPRESS_LEVEL);
		if (cmp_status != Z_OK) {
			LOGE("compress() failed!");
			SAFE_FREE(pCmp);
			goto RET;
		}
		ret = (char*)pCmp;
		*len = cmp_len;

RET:
		if (pCmp)
			hexdump(pCmp, cmp_len);
//		SAFE_FREE(plaintext);
		return ret;
#else
		hexdump(plaintext, *len);
		return plaintext;
#endif // PLAIN_DEBUG
    }
	else
	{
        char *begin = plaintext;
        while (plaintext < begin + *len)
        {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
	}
}


/*
// The string to compress.

static const char *s_pStr = "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson." \
  "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson." \
  "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson." \
  "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson." \
  "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson." \
  "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson." \
  "Good morning Dr. Chandra. This is Hal. I am ready for my first lesson.";


int main(int argc, char *argv[])
{
  uint step = 0;
  int cmp_status;
  uLong src_len = (uLong)strlen(s_pStr);
  uLong cmp_len = compressBound(src_len);
  uLong uncomp_len = src_len;
  uint8 *pCmp, *pUncomp;
  uint total_succeeded = 0;
  (void)argc, (void)argv;

  printf("miniz.c version: %s\n", MZ_VERSION);

  do
  {
    // Allocate buffers to hold compressed and uncompressed data.
    pCmp = (mz_uint8 *)malloc((size_t)cmp_len);
    pUncomp = (mz_uint8 *)malloc((size_t)src_len);
    if ((!pCmp) || (!pUncomp))
    {
      printf("Out of memory!\n");
      return EXIT_FAILURE;
    }

    // Compress the string.
    cmp_status = compress(pCmp, &cmp_len, (const unsigned char *)s_pStr, src_len);
    if (cmp_status != Z_OK)
    {
      printf("compress() failed!\n");
      free(pCmp);
      free(pUncomp);
      return EXIT_FAILURE;
    }

    printf("Compressed from %u to %u bytes\n", (mz_uint32)src_len, (mz_uint32)cmp_len);

    if (step)
    {
      // Purposely corrupt the compressed data if fuzzy testing (this is a very crude fuzzy test).
      uint n = 1 + (rand() % 3);
      while (n--)
      {
        uint i = rand() % cmp_len;
        pCmp[i] ^= (rand() & 0xFF);
      }
    }

    // Decompress.
    cmp_status = uncompress(pUncomp, &uncomp_len, pCmp, cmp_len);
    total_succeeded += (cmp_status == Z_OK);

    if (step)
    {
      printf("Simple fuzzy test: step %u total_succeeded: %u\n", step, total_succeeded);
    }
    else
    {
      if (cmp_status != Z_OK)
      {
        printf("uncompress failed!\n");
        free(pCmp);
        free(pUncomp);
        return EXIT_FAILURE;
      }

      printf("Decompressed from %u to %u bytes\n", (mz_uint32)cmp_len, (mz_uint32)uncomp_len);

      // Ensure uncompress() returned the expected data.
      if ((uncomp_len != src_len) || (memcmp(pUncomp, s_pStr, (size_t)src_len)))
      {
        printf("Decompression failed!\n");
        free(pCmp);
        free(pUncomp);
        return EXIT_FAILURE;
      }
    }

    free(pCmp);
    free(pUncomp);

    step++;

    // Keep on fuzzy testing if there's a non-empty command line.
  } while (argc >= 2);

  printf("Success.\n");
  return EXIT_SUCCESS;
}
*/
