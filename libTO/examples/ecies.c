/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2021 Trusted Objects. All rights reserved.
 */

/**
 * @file ecies.c
 * @brief Simple client/server ECIES example using Trusted Objects library.
 */

#include "TO.h"
#include "TO_driver.h"
#include "TO_retcodes.h"

#include "ecies.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* GenericCertificate-00021000020007A8 */
#define CERT_X509 (uint8_t[]){                                                                      \
    0x30, 0x82, 0x01, 0xc6, 0x30, 0x82, 0x01, 0x6d, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x07, 0x02, \
    0x10, 0x00, 0x02, 0x00, 0x07, 0xa8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, \
    0x03, 0x02, 0x30, 0x6a, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x13, 0x47, \
    0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x73, 0x5f, 0x41, \
    0x57, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x05, 0x41, 0x76, 0x6e, \
    0x65, 0x74, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x10, 0x4d, 0x75, 0x6e, \
    0x69, 0x63, 0x68, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x31, 0x1f, 0x30, \
    0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x41, 0x76, 0x6e, 0x65, 0x74, 0x20, 0x30, 0x30, \
    0x30, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x22, \
    0x18, 0x0f, 0x32, 0x30, 0x31, 0x34, 0x30, 0x31, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, \
    0x5a, 0x18, 0x0f, 0x33, 0x30, 0x30, 0x30, 0x31, 0x32, 0x32, 0x39, 0x32, 0x33, 0x35, 0x39, 0x35, \
    0x39, 0x5a, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x18, 0x47, \
    0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2d, 0x30, 0x30, 0x30, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, \
    0x32, 0x30, 0x30, 0x30, 0x37, 0x41, 0x38, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, \
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, \
    0x00, 0x04, 0x51, 0x08, 0x9c, 0x4e, 0xad, 0xfe, 0x69, 0x27, 0xd7, 0x19, 0x04, 0x42, 0x77, 0x15, \
    0xbf, 0xb9, 0x80, 0x38, 0x24, 0xa7, 0x7d, 0xcb, 0x1e, 0xa8, 0xa5, 0x53, 0xc3, 0x40, 0xa4, 0x88, \
    0xf3, 0xc5, 0x03, 0x8e, 0x64, 0x46, 0x9d, 0x29, 0xa5, 0x3d, 0x31, 0x9a, 0x6b, 0x76, 0x37, 0x26, \
    0x46, 0x06, 0x8e, 0xfc, 0xd5, 0x84, 0x6e, 0x47, 0xd4, 0xe4, 0x1d, 0x20, 0x64, 0x48, 0x79, 0x0e, \
    0x74, 0x2b, 0xa3, 0x41, 0x30, 0x3f, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, \
    0x04, 0x04, 0x03, 0x02, 0x03, 0xc8, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, \
    0x04, 0x02, 0x30, 0x00, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, \
    0x14, 0x84, 0xe4, 0xa2, 0x47, 0xc1, 0x3d, 0xd3, 0x85, 0x01, 0x9b, 0xfd, 0x7e, 0x14, 0xbe, 0x93, \
    0x43, 0x8c, 0x6e, 0x94, 0xd8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, \
    0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x5e, 0xd3, 0x0f, 0xd8, 0x77, 0xc6, 0xa6, 0x98, \
    0xd4, 0xb6, 0x8b, 0xd4, 0x23, 0x5b, 0x43, 0xfc, 0x57, 0x93, 0xef, 0xb2, 0x06, 0x36, 0x57, 0xe5, \
    0x7a, 0xbb, 0x34, 0x87, 0xcc, 0xd7, 0x08, 0x60, 0x02, 0x20, 0x39, 0xf6, 0xf1, 0x6f, 0xfe, 0x6c, \
    0xf5, 0xb2, 0x7b, 0x3f, 0xf7, 0x80, 0x67, 0xa1, 0x6f, 0x92, 0xa3, 0xb5, 0x1e, 0x86, 0xa7, 0xf2, \
    0x92, 0x11, 0xf8, 0x7f, 0xac, 0x86, 0xdf, 0x0b, 0x16, 0x89                                      \
}
/* GenericKeyPair-00021000020007A8 */
#define CERT_KPRIV (uint8_t[]){                                                                     \
    0x3e, 0x78, 0x6e, 0x58, 0xc5, 0xc4, 0x1c, 0x2d, 0xfb, 0x8e, 0x64, 0xe3, 0xfd, 0xa0, 0xe3, 0x67, \
    0xc1, 0x2b, 0xe9, 0x14, 0x89, 0x4c, 0xff, 0xdd, 0xc5, 0xb5, 0xd0, 0xd8, 0xe8, 0x99, 0xbe, 0x94, \
}
/* Avnet-MunichProduction-Generic_Samples_AWS-CA-Certificate-0002100002000000 public key */
#define CA_KPUB (uint8_t[]){                                                                        \
    0x09, 0x39, 0x87, 0x69, 0x6d, 0xc5, 0x30, 0xb4, 0x61, 0xe3, 0x87, 0x2f, 0xe9, 0xb6, 0x45, 0x3a, \
    0xf3, 0x3b, 0xe4, 0xfc, 0x37, 0x2f, 0xba, 0x02, 0x46, 0xec, 0xd9, 0xc7, 0x2d, 0xf6, 0xd6, 0x07, \
    0x24, 0x40, 0x3a, 0x12, 0xc3, 0x4a, 0x2e, 0xc0, 0xc8, 0x48, 0x61, 0xcd, 0x1a, 0xcd, 0xbc, 0xff, \
    0x47, 0xe8, 0x8e, 0xce, 0xf3, 0x7f, 0xd5, 0x70, 0x4a, 0x26, 0xa0, 0x4e, 0x5f, 0xed, 0x82, 0x24, \
}
/* Avnet-MunichProduction-Generic_Samples_AWS-CA-Certificate-0002100002000000 subject key identifier */
#define CA_KEY_IDENTIFIER (uint8_t[]){                                                              \
    0x84, 0xe4, 0xa2, 0x47, 0xc1, 0x3d, 0xd3, 0x85, 0x01, 0x9b, 0xfd, 0x7e, 0x14, 0xbe, 0x93, 0x43, \
    0x8c, 0x6e, 0x94, 0xd8                                                                          \
}

#ifndef TO_DISABLE_ECIES_HELPER

#define LOCAL_ECC_KEY_INDEX 0
#define REMOTE_ECC_KEY_INDEX 0

#define USE_AUTH
#define USE_X509

#define HELLO_MSG "Hello!"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#if !defined(TO_ECIES_CLIENT) && !defined(TO_ECIES_SERVER)
#error "You must define device type ('TO_ECIES_CLIENT' or 'TO_ECIES_SERVER')"
#endif

#ifdef USE_AUTH
static uint8_t buf[1024];

typedef enum data_type_e {
	ECIES_CHALLENGE,
	ECIES_CERTIFICATE_AND_SIGN,
	ECIES_KEY,
	ECIES_CYPHERED_DATA
} data_type_t;

typedef enum step_e {
	ECIES_AUTH_INIT,
	ECIES_AUTH_PEER,
	ECIES_AUTH_LOCAL,
	ECIES_KEY_PEER,
	ECIES_KEY_LOCAL,
	ECIES_DONE
} step_t;

static int auth_local(void)
{
	TO_ret_t ret;
	payload_t *payload = (payload_t*)buf;
	uint16_t len;
	uint8_t signature[TO_SIGNATURE_SIZE];
	uint16_t signature_len = TO_SIGNATURE_SIZE;
	uint16_t cert_len = 0;

	/* Receive peer challenge */
	if (recv_data((uint8_t*)payload, sizeof(buf), &len) != 0) {
		fprintf(stderr, "recv_data() failed\n");
		return -1;
	}
	ASSERT(payload->data_type == ECIES_CHALLENGE);
	ASSERT(DATA_SIZE(payload) == TO_CHALLENGE_SIZE);

	/* Sign peer challenge and return certificate */
	if ((ret = TOSE_get_certificate_x509_and_sign(DEFAULT_CTX, 0,
			payload->data,
			TO_CHALLENGE_SIZE,
			payload->data,
			&cert_len,
			signature,
			&signature_len)) != TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_get_certificate_and_sign() with error %02x\n", ret);

		return -1;
	}
	memcpy(payload->data + cert_len, signature, TO_SIGNATURE_SIZE);
	payload->data_type = ECIES_CERTIFICATE_AND_SIGN;
	payload->data_size = htobe16(cert_len + TO_SIGNATURE_SIZE);
	if (send_data((uint8_t*)payload, PAYLOAD_SIZE(payload)) != 0) {
		fprintf(stderr, "send_data() failed\n");

		return -1;
	}

	return 0;
}

static int auth_peer(void)
{
	TO_ret_t ret;
	payload_t *payload = (payload_t*)buf;
	uint16_t len = 0;

	/* Get the challenge's length */
	if ((ret = TOSE_get_challenge_and_store(DEFAULT_CTX, payload->data, &len)) != TORSP_INVALID_OUTPUT_LEN) {
		fprintf(stderr, "TOSE_get_challenge_and_store() failed with error "
		                "%02x\n", ret);

		return -1;
	}

	/* Get the challenge */
	if ((ret = TOSE_get_challenge_and_store(DEFAULT_CTX, payload->data, &len)) != TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_get_challenge_and_store() failed with error "
		                "%02x\n", ret);

		return -1;
	}
	payload->data_size = len;
	payload->data_type = ECIES_CHALLENGE;
	if (send_data((uint8_t*)payload, PAYLOAD_SIZE(payload)) != 0) {
		fprintf(stderr, "send_data() failed\n");

		return -1;
	}

	/* Verify peer certificate and signature */
	if (recv_data((uint8_t*)payload, sizeof(buf), &len) != 0) {
		fprintf(stderr, "recv_data() failed\n");

		return -1;
	}
	ASSERT(payload->data_type == ECIES_CERTIFICATE_AND_SIGN);
	if ((ret = TOSE_verify_certificate_and_store(DEFAULT_CTX,
			0,
			TO_CERTIFICATE_X509,
			payload->data,
			payload->data_size)) != TORSP_SUCCESS) {
			fprintf(stderr, "TOSE_verify_certificate_and_store() failed with error "
		                "%02x\n", ret);

		return -1;
	}
	if ((ret = TOSE_verify_challenge_signature(DEFAULT_CTX, payload->data +
					DATA_SIZE(payload) - TO_SIGNATURE_SIZE)) != TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_verify_challenge_signature() failed with error "
		                "%02x\n", ret);

		return -1;
	}

	return 0;
}

static int auth_key_local(void)
{
	TO_ret_t ret;
	payload_t *payload = (payload_t*)buf;
	uint16_t public_key_length = TO_ECC_PUB_KEYSIZE;
	uint16_t signature_length = TO_SIGNATURE_SIZE;

	/* Renew ephemeral key pair */
	if ((ret = TOSE_renew_ecc_keys(DEFAULT_CTX, LOCAL_ECC_KEY_INDEX)) != TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_renew_ecc_keys() failed with error "
		                "%02x\n", ret);

		return -1;
	}

	/* Send signed public key */
	if ((ret = TOSE_get_public_key(DEFAULT_CTX,
			LOCAL_ECC_KEY_INDEX,
			payload->data,
			&public_key_length,
			payload->data + TO_ECC_PUB_KEYSIZE,
			&signature_length)) != TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_get_public_key() failed with error "
		                "%02x\n", ret);

		return -1;
	}
	payload->data_type = ECIES_KEY;
	payload->data_size = htobe16(TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE);
	if (send_data((uint8_t*)payload, PAYLOAD_SIZE(payload)) != 0) {
		fprintf(stderr, "send_data() failed\n");

		return -1;
	}

	return 0;
}

static int auth_key_peer(void)
{
	TO_ret_t ret;
	uint16_t len;
	payload_t *payload = (payload_t*)buf;

	/* Receive peer key and signature */
	if (recv_data((uint8_t*)payload, sizeof(buf), &len) != 0) {
		fprintf(stderr, "recv_data() failed\n");

		return -1;
	}
	ASSERT(payload->data_type == ECIES_KEY);
	ASSERT(DATA_SIZE(payload) == TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE);

	/* Verify peer key */
	if ((ret = TOSE_set_remote_public_key(DEFAULT_CTX, REMOTE_ECC_KEY_INDEX, payload->data,
					payload->data + TO_ECC_PUB_KEYSIZE)) != TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_set_remote_public_key() failed with error "
		                "%02x\n", ret);

		return -1;
	}

	return 0;
}

static int auth(void)
{
	int ret;
	TO_ret_t ret2;
	static step_t step = ECIES_AUTH_INIT;

	if (step == ECIES_DONE) {
		return 0;
	}

#ifdef TO_ECIES_CLIENT
	step = ECIES_AUTH_PEER;
#else
	step = ECIES_AUTH_LOCAL;
#endif

	while (step != ECIES_DONE) {

		switch (step) {

			/* Authentication of local device to remote device */
			case ECIES_AUTH_LOCAL:
				if ((ret = auth_local()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_KEY_PEER;
#else
				step = ECIES_AUTH_PEER;
#endif
				break;

			/* Authentication of remote device to local device */
			case ECIES_AUTH_PEER:
				if ((ret = auth_peer()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_AUTH_LOCAL;
#else
				step = ECIES_KEY_LOCAL;
#endif
				break;

			/* Exchange of remote device ephemeral public key */
			case ECIES_KEY_PEER:
				if ((ret = auth_key_peer()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_KEY_LOCAL;
#else
				step = ECIES_DONE;
#endif
				break;

			/* Exchange of local device ephemeral public key */
			case ECIES_KEY_LOCAL:
				if ((ret = auth_key_local()) != 0) {
					return ret;
				}
#ifdef TO_ECIES_CLIENT
				step = ECIES_DONE;
#else
				step = ECIES_KEY_PEER;
#endif
				break;

			default:
				fprintf(stderr, "Un-expexted step %d\n", step);
				return -1;
		}
	}

	/* Calculate shared key */
	if ((ret2 = TOSE_renew_shared_keys(DEFAULT_CTX, LOCAL_ECC_KEY_INDEX, REMOTE_ECC_KEY_INDEX))
			!= TORSP_SUCCESS) {
		fprintf(stderr, "TOSE_renew_shared_keys() failed with error "
		                "%02x\n", ret2);
		return -1;
	}

	return 0;
}

#if !defined(TO_DISABLE_CAPI) && !defined(TO_DISABLE_SECURE_PAYLOAD_HELPER)
#define RET_T TO_lib_ret_t
#define SECURE_PAYLOAD(...) TOSE_helper_secure_payload(DEFAULT_CTX, __VA_ARGS__)
#define UNSECURE_PAYLOAD(...) TOSE_helper_unsecure_payload(DEFAULT_CTX, __VA_ARGS__)
#define SECURE_PAYLOAD_EXP_RET TO_OK
#else
#define RET_T TO_ret_t
#define SECURE_PAYLOAD(...) TOSE_secure_payload(DEFAULT_CTX, __VA_ARGS__)
#define UNSECURE_PAYLOAD(...) TOSE_unsecure_payload(DEFAULT_CTX, __VA_ARGS__)
#define SECURE_PAYLOAD_EXP_RET TORSP_SUCCESS
#endif

/**
 * Simple secure function:
 * - Pad data (padding length >= 1) with padding length
 * - Secure message (encryption and authentication)
 */
static int encrypt(const uint8_t *data, const uint16_t data_len,
		uint8_t *data_encrypted, uint16_t *data_encrypted_len)
{
	RET_T ret;

	/* Secure message */
	if ((ret = SECURE_PAYLOAD(LOCAL_ECC_KEY_INDEX,
			TO_SECMSG_ALG_AES128CBC_HMAC,
			data, data_len,
			data_encrypted, data_encrypted_len)) != SECURE_PAYLOAD_EXP_RET) {
		fprintf(stderr, "Secure payload failed with error "
		                "%04x\n", ret);
		return -1;
	}

	return 0;
}

/**
 * Simple un-secure function:
 * - Un-secure message (authentication and decryption)
 * - Remove data padding
 */
static int decrypt(const uint8_t *data_encrypted, const uint16_t data_encrypted_len,
		uint8_t *data, uint16_t *data_len)
{
	RET_T ret;

	/* Unsecure message */
	if ((ret = UNSECURE_PAYLOAD(LOCAL_ECC_KEY_INDEX,
			TO_SECMSG_ALG_AES128CBC_HMAC,
			data_encrypted, data_encrypted_len,
			data, data_len)) != SECURE_PAYLOAD_EXP_RET) {
		fprintf(stderr, "Unsecure payload failed with error "
		                "%04x\n", ret);
		return -1;
	}

	return 0;
}

/**
 * Simple function to send data with authentication and encryption.
 */
static int send_data_with_auth(const uint8_t *data, const uint16_t data_len)
{
	int ret = 0;
	payload_t *payload = (payload_t*)buf;
	uint8_t *data_encrypted = payload->data;
	uint16_t data_encrypted_len;

	/* Mutual authentication */
	if ((ret = auth()) != 0) {
		fprintf(stderr, "auth() failed\n");
		return ret;
	}

	/* Encrypt data */
	if ((ret = encrypt(data, data_len, data_encrypted, &data_encrypted_len))
			!= 0) {
		fprintf(stderr, "encrypt() failed\n");
		return ret;
	}

	payload->data_type = ECIES_CYPHERED_DATA;
	payload->data_size = htobe16(data_encrypted_len);

	/* Send encrypted data */
	if ((ret = send_data((uint8_t*)payload, PAYLOAD_SIZE(payload))) != 0) {
		fprintf(stderr, "send_data() failed\n");
		return ret;
	}

	return 0;
}

/**
 * Simple function to receive data with authentication and encryption.
 */
static int recv_data_with_auth(uint8_t *data, const uint16_t max_len,
		uint16_t *data_len)
{
	int ret = 0;
	uint16_t len;
	payload_t *payload = (payload_t*)buf;

	/* Mutual authentication */
	if ((ret = auth()) != 0) {
		fprintf(stderr, "auth() failed\n");
		return ret;
	}

	/* Receive encrypted data */
	if ((ret = recv_data((uint8_t*)payload, sizeof(buf), &len)) != 0) {
		fprintf(stderr, "recv_data() failed\n");
		return ret;
	}
	ASSERT((data_type_t)payload->data_type == ECIES_CYPHERED_DATA);
	ASSERT((uint16_t)DATA_SIZE(payload) <= max_len + TO_AES_BLOCK_SIZE -
			(max_len % TO_AES_BLOCK_SIZE) + TO_HMAC_SIZE);

	/* Decrypt data */
	if ((ret = decrypt(payload->data, DATA_SIZE(payload), data, data_len))
			!= 0) {
		fprintf(stderr, "decrypt() failed\n");
		return ret;
	}

	return 0;
}

#define SEND_DATA send_data_with_auth
#define RECV_DATA recv_data_with_auth

#else

#define SEND_DATA send_data
#define RECV_DATA recv_data

#endif

int main(int argc, const char *argv[])
{
	uint8_t data[256];
	uint16_t data_len;
	TO_ret_t ret = TORSP_INTERNAL_ERROR;

	if (TOSE_init(DEFAULT_CTX) != TO_OK) {
		fprintf(stderr, "TOSE_init() failed with error "
		                "%04x\n", ret);
		goto fail;
	}

	if (init_data(argc, argv) != 0) {
		fprintf(stderr, "init_data() failed\n");
		goto fail1;
	}

#ifdef TO_ECIES_CLIENT
	/* Send message */
	if (SEND_DATA((const uint8_t*)HELLO_MSG, sizeof(HELLO_MSG)) != 0) {
		fprintf(stderr, "SEND_DATA() failed\n");
		goto fail2;
	}
	/* Receive message */
	if (RECV_DATA(data, sizeof(data), &data_len) != 0) {
		fprintf(stderr, "RECV_DATA() failed\n");
		goto fail2;
	}
	fprintf(stderr, "data:\n------------\n%s\n------------\n", data);
#else
	/* Receive message */
	if (RECV_DATA(data, sizeof(data), &data_len) != 0) {
		fprintf(stderr, "RECV_DATA() failed\n");
		goto fail2;
	}
	fprintf(stderr, "data:\n------------\n%s\n------------\n", data);
	/* Send message */
	if (SEND_DATA((const uint8_t*)HELLO_MSG, sizeof(HELLO_MSG)) != 0) {
		fprintf(stderr, "SEND_DATA() failed\n");
		goto fail2;
	}
#endif

	ret = TORSP_SUCCESS;

fail2:
	if (fini_data() != TO_OK) {
		fprintf(stderr, "fini_data() failed\n");
	}
fail1:
	if (TOSE_fini(DEFAULT_CTX) != TO_OK) {
		fprintf(stderr, "TOSE_fini() failed\n");
	}
fail:
	return (ret == TORSP_SUCCESS ? 0 : ret);
}

#else
#error ECIES helper need to be built in order to compile ecies.c example
#endif

