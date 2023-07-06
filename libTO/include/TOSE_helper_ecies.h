/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019 Trusted Objects. All rights reserved.
 */

/**
 * @file TOSE_helper_ecies.h
 * @brief
 */

#ifndef _TOSE_HELPER_ECIES_H_
#define _TOSE_HELPER_ECIES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"
#include "TO_retcodes.h"

/** @addtogroup helper_ecies_auth_se
 * @{ */

/**
 * @brief ECIES sequence (1st step):
 * authenticate Secure Element
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_index Index of the Secure Element certificate to use
 * @param[in] challenge Challenge (randomly generated) to be provided to the Secure
 * Element
 * @param[out] TO_certificate Short certificate returned by Secure Element
 * @param[out] challenge_signature Signature of the challenge by Secure Element
 *
 * This is the ECIES sequence first step, which aims to authenticate Secure
 * Element.
 * It provides a challenge to Secure Element, and get back its certificate and
 * the challenge signed using the private key associated to the certificate.
 *
 * Refer to Secure Element Datasheet Application Notes - Authenticate Secure
 * Element (and also optimized scheme).
 *
 * Before call you need to:
 * - randomly generate a challenge
 * After call you need to:
 * - check return value (see below)
 * - verify Secure Element certificate signature using CA public key
 * - verify challenge signature using Secure Element certificate public key
 * if previous steps are validated, continue with the next ECIES step:
 * TOSE_helper_ecies_seq_auth_remote_1(TOSE_ctx_t *ctx, ) to authenticate the remote device.
 *
 * @return TO_OK if this step is passed successfully.
 */
extern TO_lib_ret_t TOSE_helper_ecies_seq_auth_SE(TOSE_ctx_t *ctx, uint8_t certificate_index,
		uint8_t challenge[TO_CHALLENGE_SIZE],
		uint8_t *se_certificate,
		uint16_t *se_certificate_length,
		uint8_t challenge_signature[TO_SIGNATURE_SIZE]);

/* @} */

/** @addtogroup helper_ecies_auth_remote
 * @{ */

/**
 * @brief ECIES sequence (2nd step):
 * authenticate remote device against Secure Element (part 1)
 * @param[in] ctx Pointer to the SE context
 * @param[in] ca_pubkey_index Index of Certificate Authority public key
 * @param[in] remote_certificate Remote device x509 certificate
 * @param[out] challenge Challenge returned by Secure Element to authenticate remote
 * device
 *
 * This is the ECIES sequence second step, which aims to authenticate remote
 * device (server or other connected object).
 * This first part provides remote device certificate to Secure Element, and
 * get back a random challenge which is going to be used later to authenticate
 * remote device.
 *
 * There is only one remote certificate at a time. If several shared keys are
 * needed, we can overwrite remote certificate after shared keys computing.
 *
 * Refer to Secure Element Datasheet Application Notes - Authenticate Remote
 * Device.
 *
 * Before call you need to:
 * - have completed previous ECIES sequence steps
 * - have the remote device certificate
 * After call you need to:
 * - check return value (see below)
 * - sign the returned challenge using the remote device certificate private key
 * if previous steps are validated, continue with
 * TOSE_helper_ecies_seq_auth_remote_2(TOSE_ctx_t *ctx, ) to finalize remote device
 * authentication.
 *
 * @return TO_OK if this step is passed successfully, else:
 * - TORSP_BAD_SIGNATURE: the remote device certificate CA signature is
 *   invalid
 */
extern TO_lib_ret_t TOSE_helper_ecies_seq_auth_remote_1(TOSE_ctx_t *ctx, uint8_t ca_pubkey_index,
		const uint8_t *remote_certificate,
		const uint16_t remote_certificate_length,
		uint8_t challenge[TO_CHALLENGE_SIZE]);

/**
 * @brief ECIES sequence (2nd step):
 * authenticate remote
 * device against Secure Element (part 2)
 * @param[in] ctx Pointer to the SE context
 * @param[in] challenge_signature Challenge signed using remote device certificate
 * private key
 *
 * This is the ECIES sequence second step, which aims to authenticate remote
 * device (server or other connected object).
 * This second part provides challenge signed using remote device certificate
 * private key.
 *
 * Refer to Secure Element Datasheet Application Notes - Authenticate Remote
 * Device.
 *
 * Before call you need to:
 * - have completed previous ECIES sequence steps
 * - compute the challenge signature
 * After call you need to:
 * - check return value (see below)
 * if previous steps are validated, continue with
 * TOSE_helper_ecies_seq_secure_messaging(TOSE_ctx_t *ctx, ).
 *
 * @return TO_OK if this step is passed successfully, else:
 * - TORSP_BAD_SIGNATURE: the challenge signature is invalid
 */
extern TO_lib_ret_t TOSE_helper_ecies_seq_auth_remote_2(TOSE_ctx_t *ctx,
		uint8_t challenge_signature[TO_SIGNATURE_SIZE]);

/* @} */

/** @addtogroup helper_ecies_secmsg
 * @{ */

/**
 * @brief ECIES sequence (3rd step):
 * prepare secure data exchange.
 * @param[in] ctx Pointer to the SE context
 * @param[in] remote_pubkey_index Index where the public key will be stored
 * @param[in] ecc_keypair_index Index of the ECC key pair to renew
 * @param[in] remote_eph_pubkey Remote device ephemeral public key
 * @param[in] remote_eph_pubkey_signature Remote device ephemeral public key
 * signature
 * @param[out] TO_eph_pubkey Returned Secure Element ephemeral public key
 * @param[out] TO_eph_pubkey_signature Secure Element ephemeral public key signature
 *
 * This is the ECIES sequence third step, which aims to prepare secure
 * messaging. Server and connected object will be able to securely exchange
 * data.
 * It provides remote device ephemeral public key signed using remote device
 * certificate private key, and get back Secure Element ephemeral public key.
 *
 * Secure Element public keys, AES keys, and HMAC keys have the same index to
 * use them from Secure Element APIs.
 *
 * Refer to Secure Element Datasheet Application Notes - Secure Messaging.
 *
 * Before call you need to:
 * - have completed previous ECIES sequence steps
 * - generate ephemeral key pair
 * - sign the ephemeral public key using remote device certificate private key.
 *
 * After call you need to:
 * - check return value (see below)
 * - check Secure Element ephemeral public key signature using Secure Element
 *   certificate public key
 * - compute shared secret using remote device and Secure Element ephemeral
 *   public keys
 * - derive shared secret with SHA256 to get AES and HMAC keys
 *
 * If previous steps are validated, AES and HMAC keys can be used for secure
 * messaging.
 *
 * @return TO_OK if this step is passed successfully, else:
 * - TORSP_BAD_SIGNATURE: the remote device public key signature is invalid
 */
extern TO_lib_ret_t TOSE_helper_ecies_seq_secure_messaging(TOSE_ctx_t *ctx,
		uint8_t remote_pubkey_index, uint8_t ecc_keypair_index,
		uint8_t remote_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t remote_eph_pubkey_signature[TO_SIGNATURE_SIZE],
		uint8_t TO_eph_pubkey[TO_ECC_PUB_KEYSIZE],
		uint8_t TO_eph_pubkey_signature[TO_SIGNATURE_SIZE]);

/* @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_HELPER_ECIES_H_ */

