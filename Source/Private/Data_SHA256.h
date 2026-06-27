#pragma once

#include <stdint.h>
#include <string.h>

/*
* Data_SHA256
* Copyright (C) 2016, Thomas Shepherd <Thomas.Shepherd@Matchoo.org>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. Neither the name of the project nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

#define SHA256_BLOCK_SIZE  ( 512 / 8)
#define SHA256_DIGEST_SIZE (256 / 8)

namespace ogayImpl
{
	/*
	* FIPS 180-2 SHA-224/256/384/512 implementation
	* Last update: 02/02/2007
	* Issue date:  04/30/2005
	*
	* Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
	* All rights reserved.
	*
	* Redistribution and use in source and binary forms, with or without
	* modification, are permitted provided that the following conditions
	* are met:
	* 1. Redistributions of source code must retain the above copyright
	*    notice, this list of conditions and the following disclaimer.
	* 2. Redistributions in binary form must reproduce the above copyright
	*    notice, this list of conditions and the following disclaimer in the
	*    documentation and/or other materials provided with the distribution.
	* 3. Neither the name of the project nor the names of its contributors
	*    may be used to endorse or promote products derived from this software
	*    without specific prior written permission.
	*
	* THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
	* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	* ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
	* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
	* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
	* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
	* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
	* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
	* SUCH DAMAGE.
	*/

	typedef struct {
		unsigned int tot_len;
		unsigned int len;
		uint8_t block[2 * SHA256_BLOCK_SIZE];
		uint32_t h[8];
	} sha256_ctx;

	typedef struct {
		sha256_ctx ctx_inside;
		sha256_ctx ctx_outside;

		/* for hmac_reinit */
		sha256_ctx ctx_inside_reinit;
		sha256_ctx ctx_outside_reinit;

		uint8_t block_ipad[SHA256_BLOCK_SIZE];
		uint8_t block_opad[SHA256_BLOCK_SIZE];
	} hmac_sha256_ctx;

	void sha256_init(sha256_ctx *ctx);
	void sha256_update(sha256_ctx *ctx, const uint8_t *message,
		unsigned int len);
	void sha256_final(sha256_ctx *ctx, uint8_t *digest);
	void sha256(const uint8_t *message, unsigned int len,
		uint8_t *digest);
	void hmac_sha256_init(hmac_sha256_ctx *ctx, const uint8_t *key,
		unsigned int key_size);
	void hmac_sha256_reinit(hmac_sha256_ctx *ctx);
	void hmac_sha256_update(hmac_sha256_ctx *ctx, const uint8_t *message,
		unsigned int message_len);
	void hmac_sha256_final(hmac_sha256_ctx *ctx, uint8_t *mac,
		unsigned int mac_size);
	void hmac_sha256(const uint8_t *key, unsigned int key_size,
		const uint8_t *message, unsigned int message_len,
		uint8_t *mac, unsigned mac_size);
}
