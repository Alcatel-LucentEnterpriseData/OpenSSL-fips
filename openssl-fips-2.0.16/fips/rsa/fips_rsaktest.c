/* fips_rsaktest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#ifndef OPENSSL_FIPS

int main(int argc, char *argv[])
{
    printf("No FIPS RSA support\n");
    return(0);
}

#else

#include <openssl/rsa.h>
#include <openssl/fips.h>
#include "fips_utl.h"

static int rsa_ktest(FILE *out, FILE *in);

#ifdef FIPS_ALGVS
int fips_rsaktest_main(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
	{
	FILE *in = NULL, *out = NULL;

	int ret = 1;

	fips_algtest_init();

	if (argc == 1)
		in = stdin;
	else
		in = fopen(argv[1], "r");

	if (argc < 2)
		out = stdout;
	else
		out = fopen(argv[2], "w");

	if (!in)
		{
		fprintf(stderr, "FATAL input initialization error\n");
		goto end;
		}

	if (!out)
		{
		fprintf(stderr, "FATAL output initialization error\n");
		goto end;
		}

	if (!rsa_ktest(out, in))
		{
		fprintf(stderr, "FATAL RSAKTEST file processing error\n");
		goto end;
		}
	else
		ret = 0;

	end:

	if (in && (in != stdin))
		fclose(in);
	if (out && (out != stdout))
		fclose(out);

	return ret;

	}

#define RSA_TEST_MAXLINELEN	10240

int rsa_ktest(FILE *out, FILE *in)
	{
	char *linebuf, *olinebuf, *p, *q;
	char *keyword, *value;
	int i, count;
	RSA *rsa = NULL;
	int keylen = -1, current_keylen = -1;
	BIGNUM *e = NULL;
	int ret = 0;
	int lnum = 0;

	olinebuf = OPENSSL_malloc(RSA_TEST_MAXLINELEN);
	linebuf = OPENSSL_malloc(RSA_TEST_MAXLINELEN);

	if (!linebuf || !olinebuf)
		goto error;

	while (fgets(olinebuf, RSA_TEST_MAXLINELEN, in))
		{
		lnum++;
		strcpy(linebuf, olinebuf);
		keyword = linebuf;
		/* Skip leading space */
		while (isspace((unsigned char)*keyword))
			keyword++;

		/* Look for = sign */
		p = strchr(linebuf, '=');

		/* If no = just copy */
		if (!p)
			{
			if (fputs(olinebuf, out) < 0)
				goto error;
			continue;
			}

		q = p - 1;

		/* Remove trailing space */
		while (isspace((unsigned char)*q))
			*q-- = 0;

		*p = 0;
		value = p + 1;

		/* Remove leading space from value */
		while (isspace((unsigned char)*value))
			value++;

		/* Remove trailing space from value */
		p = value + strlen(value) - 1;

		while (*p == '\n' || isspace((unsigned char)*p))
			*p-- = 0;

		/* Look for [mod = XXX] for key length */

		if (!strcmp(keyword, "[mod"))
			{
			p = value + strlen(value) - 1;
			if (*p != ']')
				goto parse_error;
			*p = 0;
			keylen = atoi(value);
			if (keylen < 0)
				goto parse_error;
			}

		if (!strcmp(keyword, "N"))
			{
			count = atoi(value);
                        e = BN_new();
                        if (!e)
                                goto error;
                        BN_set_word(e, 65537);

			for (i = 0; i < count; i++)
				{

		        	rsa = FIPS_rsa_new();
			        if (!rsa)
				        goto error;
                                if (!RSA_generate_key_ex(rsa, keylen, e, NULL))
				        goto error;
				do_bn_print_name(out, "e", rsa->e);
				do_bn_print_name(out, "p", rsa->p);
				do_bn_print_name(out, "q", rsa->q);
				do_bn_print_name(out, "n", rsa->n);
				do_bn_print_name(out, "d", rsa->d);
				fputs(RESP_EOL, out);
  	                        FIPS_rsa_free(rsa);
                                rsa = NULL;

				}
                        BN_free(e);
                        e = NULL;
                        continue;

			}
		fputs(olinebuf, out);
		}

	ret = 1;

	error:

	if (olinebuf)
		OPENSSL_free(olinebuf);
	if (linebuf)
		OPENSSL_free(linebuf);
	if (rsa)
		FIPS_rsa_free(rsa);
	if (e)
                BN_free(e);

	return ret;

	parse_error:

	fprintf(stderr, "FATAL parse error processing line %d\n", lnum);

	goto error;

	}

#endif
