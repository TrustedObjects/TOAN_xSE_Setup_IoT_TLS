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
 * @file helper_ecies.c
 * @brief Secure Element ECIES helper, besed on Secure Element APIs to simplify
 * ECIES sequence.
 */

#include "TO.h"
#include "TO_helper.h"

#ifndef TO_DISABLE_ECIES_HELPER

/* Dependency checks */
#ifdef TO_DISABLE_CERT_MGMT
#error Certificates management APIs must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_GET_CERTIFICATE_AND_SIGN
#error TOSE_get_certificate_and_sign API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_VERIFY_CERTIFICATE_AND_STORE
#error TOSE_verify_certificate_and_store API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_GET_CHALLENGE_AND_STORE
#error TOSE_get_challenge_and_store API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_VERIFY_CHALLENGE_SIGNATURE
#error TOSE_verify_challenge_signature API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_KEYS_MGMT
#error Keys management APIs must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_SET_REMOTE_PUBLIC_KEY
#error TOSE_set_remote_public_key API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_RENEW_ECC_KEYS
#error TOSE_renew_ecc_keys API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_RENEW_SHARED_KEYS
#error TOSE_renew_shared_keys API must be enabled for ECIES helper
#endif
#ifdef TO_DISABLE_API_GET_PUBLIC_KEY
#error TOSE_get_public_key API must be enabled for ECIES helper
#endif

TO_lib_ret_t TOSE_helper_ecies_seq_auth_SE(TOSE_ctx_t *ctx, uint8_t certificate_index,
		uint8_t challenge[TO_CHALLENGE_SIZE],
		uint8_t *se_certificate,
		uint16_t *se_certificate_length,
		uint8_t challenge_signature[TO_SIGNATURE_SIZE])
{
	TO_ret_t ret;
	uint16_t signature_length = TO_SIGNATURE_SIZE;

	ret = TOSE_get_certificate_x509_and_sign(ctx, certificate_index,
		challenge, TO_CHALLENGE_SIZE,
		se_certificate, se_certificate_length,
		challenge_signature, &signature_length);
	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("ECIES seq. error: unable to get Secure Element "
				"certificate, error %X", ret);

		return TO_ERROR | ret;
	}

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_ecies_seq_auth_remote_1(TOSE_ctx_t *ctx, uint8_t ca_pubkey_index,
		const uint8_t *remote_certificate,
		const uint16_t remote_certificate_length,
		uint8_t challenge[TO_CHALLENGE_SIZE])
{
	TO_ret_t ret;

	ret = TOSE_verify_certificate_and_store(ctx,
			ca_pubkey_index,
			TO_CERTIFICATE_X509,
			remote_certificate,
			remote_certificate_length);
	if (ret == TORSP_BAD_SIGNATURE) {
		TO_LOG_ERR("ECIES seq. error: invalid remote certificate "
				"CA signature",0);

		return (TO_lib_ret_t)TORSP_BAD_SIGNATURE;
	} else {
		if (ret != TORSP_SUCCESS) {
			TO_LOG_ERR("ECIES seq. error: unable to verify and store "
					"remote certificate, error %X", ret);

			return TO_ERROR | ret;
		}
	}
	uint16_t challenge_length = TO_CHALLENGE_SIZE;
	ret = TOSE_get_challenge_and_store(ctx, challenge, &challenge_length);
	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("ECIES seq. error: unable to get challenge "
				"from TO, error %X", ret);

		return TO_ERROR | ret;
	}

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_ecies_seq_auth_remote_2(TOSE_ctx_t *ctx,
		uint8_t challenge_signature[TO_SIGNATURE_SIZE])
{
	TO_ret_t ret;

	ret = TOSE_verify_challenge_signature(ctx, challenge_signature);
	if (ret == TORSP_BAD_SIGNATURE) {
		TO_LOG_ERR("ECIES seq. error: bad challenge signature",0);

		return (TO_lib_ret_t)TORSP_BAD_SIGNATURE;
	} else {
		if (ret != TORSP_SUCCESS) {
			TO_LOG_ERR("ECIES seq. error: unable to verify challenge "
					"signature, error %X", ret);

			return TO_ERROR | ret;
		}
	}

	return TO_OK;
}

TO_lib_ret_t TOSE_helper_ecies_seq_secure_messaging(TOSE_ctx_t *ctx,
		uint8_t remote_pubkey_index, uint8_t ecc_keypair_index,
		uint8_t remote_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t remote_eph_pubkey_signature[TO_SIGNATURE_SIZE],
		uint8_t TO_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t TO_eph_pubkey_signature[TO_SIGNATURE_SIZE])
{
	TO_ret_t ret;
	uint16_t eph_pubkey_length = TO_ECC_PUB_KEYSIZE;
	uint16_t eph_pubkey_signature_length = TO_SIGNATURE_SIZE;

	ret = TOSE_set_remote_public_key(ctx,
			remote_pubkey_index,
			remote_eph_pubkey,
			remote_eph_pubkey_signature);
	if (ret == TORSP_BAD_SIGNATURE) {
		TO_LOG_ERR("ECIES seq. error: bad remote public key signature",0);

		return (TO_lib_ret_t)TORSP_BAD_SIGNATURE;
	} else {
		if (ret != TORSP_SUCCESS) {
			TO_LOG_ERR("ECIES seq. error: unable to set remote public "
					"key, error %X", ret);

		return TO_ERROR | ret;
		}
	}
	ret = TOSE_renew_ecc_keys(ctx, ecc_keypair_index);
	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("ECIES seq. error: unable to renew ECC keys, error %X", ret);

		return TO_ERROR | ret;
	}
	ret = TOSE_get_public_key(ctx,
			ecc_keypair_index,
			TO_eph_pubkey,
			&eph_pubkey_length,
			TO_eph_pubkey_signature,
			&eph_pubkey_signature_length);
	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("ECIES seq. error: unable to get Secure Element public "
				"key, error %X", ret);

		return TO_ERROR | ret;
	}
	ret = TOSE_renew_shared_keys(ctx, ecc_keypair_index, remote_pubkey_index);
	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("ECIES seq. error: unable to renew shared "
				"keys, key, error %X", ret);

		return TO_ERROR | ret;
	}

	return TO_OK;
}

#endif // TO_DISABLE_ECIES_HELPER

