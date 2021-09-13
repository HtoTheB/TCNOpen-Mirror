/******************************************************************************/
/**
 * @file            trdp_sec_utils.c
 *
 * @brief           Common utilities for TRDP secure communication
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSec prototype stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * $Id: trdp_sec_utils.c 2310 2021-09-13 11:07:39Z mohamedyoussef $
 */

/***********************************************************************************************************************
 * INCLUDES
 */

#include <string.h>

#include "trdp_sec_utils.h"
#include "trdp_private.h"
#include "vos_utils.h"
#include "tlc_if.h"
#include "trdp_types.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

/***********************************************************************************************************************
 * DEFINITIONS
 */


/***********************************************************************************************************************
 * GLOBALS
 */

/** Find the corresponding secure session for a given IP address
 *
 *  @param[in]      appHandle       		session pointer
 *  @param[in]      addr          			IP address of the secure session
 *  @param[out]     ppElem        			pointer to the found secure session
 *  @retval         != TRDPSEC_NO_ERR  		error
 */
EXT_DECL TRDP_ERR_T trdp_sec_queueFindSecSession(
		TRDP_APP_SESSION_T 			appHandle,
		TRDP_IP_ADDR_T				addr,
		TRDPSEC_SECURE_SESSION_T *	*ppElem)
{
	TRDPSEC_SECURE_SESSION_T* iterSecHandle = *ppElem;

	if (!trdp_isValidSession(appHandle))
	{
		return TRDP_MEM_ERR;
	}

	if (appHandle->pSecQueue != NULL)
	{
		for (iterSecHandle = appHandle->pSecQueue; iterSecHandle != NULL; iterSecHandle = iterSecHandle->pNext)
		{
			/*  We match if src/dst/mc/service address is zero or matches */
			if (iterSecHandle->addr == addr)
			{
				*ppElem = iterSecHandle;
				return TRDP_NO_ERR;;
			}
		}
	}

	*ppElem = NULL;
	return TRDP_SEC_NOSESSION_ERR;
}

/**********************************************************************************************************************/
/** Add a new secure session by a given IP address
 *
 *  @param[in]      appHandle       		session pointer
 *  @param[in]      addr          			IP address of the secure session
 *  @param[in]     	secFlag					reserved for future security flags
 *  @retval         != TRDPSEC_NO_ERR  		error
 */
EXT_DECL TRDP_ERR_T	trdp_sec_addSecSessionByAddr (
		TRDP_APP_SESSION_T		appHandle,
		TRDP_IP_ADDR_T			addr,
		UINT32					secFlag)
{
	TRDPSEC_SECURE_SESSION_T *pSecSession;

	if (!trdp_isValidSession(appHandle))
	{
		return TRDP_NOINIT_ERR;
	}

	/*    Reserve mutual access    */
	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		return TRDP_MUTEX_ERR;
	}

	/*    Look for existing element    */
	if (trdp_sec_queueFindSecSession(appHandle, addr, &pSecSession) != TRDP_NO_ERR)
	{
		/* A secure session already exists */
		return TRDP_NOPUB_ERR;
	}

	pSecSession = (TRDPSEC_SECURE_SESSION_T*) vos_memAlloc(sizeof(TRDPSEC_SECURE_SESSION_T));

	if (pSecSession == NULL)
	{
		return TRDP_MEM_ERR;
	}

	pSecSession->addr = addr;
	pSecSession->sessionStatus = TRDPSEC_INVALID_SESSION;
	pSecSession->flags = secFlag;

	/* secret key exchange */

	trdp_sec_queueInsSecSession(&appHandle->pSecQueue, pSecSession);

	if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
	}

	return TRDP_NO_ERR;
}

/**********************************************************************************************************************/
/** Add a new secure session by a given IP address an return a pointer to the added element
 *
 *  @param[in]      appHandle       				session pointer
 *  @param[in]      addr          					IP address of the secure session
 *  @param[in]     	secFlag							reserved for future security flags
 *  @retval         TRDPSEC_SECURE_SESSION_T*  		pointer to the found secure session
 */
EXT_DECL TRDPSEC_SECURE_SESSION_T*	trdp_sec_addSecSession (
		TRDP_APP_SESSION_T		appHandle,
		TRDP_IP_ADDR_T			addr,
		UINT32					secFlag)
{
	TRDP_ERR_T err = TRDP_NO_ERR;
	TRDPSEC_SECURE_SESSION_T *pSecSession = NULL;

	if (!trdp_isValidSession(appHandle))
	{
		return NULL;
	}

	/*    Reserve mutual access    */
	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		/* add the logs here */
		return NULL;
	}

	/*    Look for existing element    */
	err = trdp_sec_queueFindSecSession(appHandle, addr, &pSecSession);
	if ((err != TRDP_NO_ERR) && (err != TRDP_SEC_NOSESSION_ERR))
	{
		return NULL;
	}

	if (pSecSession != NULL)
	{
		/* A secure session already exists */
		return pSecSession;
	}

	pSecSession = (TRDPSEC_SECURE_SESSION_T*) vos_memAlloc(sizeof(TRDPSEC_SECURE_SESSION_T));

	if (pSecSession == NULL)
	{
		return NULL;
	}

	pSecSession->addr = addr;
	pSecSession->sessionStatus = TRDPSEC_INVALID_SESSION;
	pSecSession->flags = secFlag;

	/* secret key exchange */

	trdp_sec_queueInsSecSession(&appHandle->pSecQueue, pSecSession);

	if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
	}

	return pSecSession;
}

/**********************************************************************************************************************/
/** Insert an element at front of queue
 *
 *  @param[in]      ppHead          pointer to pointer to head of queue
 *  @param[in]      pNew            pointer to element to insert
 */
EXT_DECL void trdp_sec_queueInsSecSession(
		TRDPSEC_SECURE_SESSION_T    * *ppHead,
		TRDPSEC_SECURE_SESSION_T    *pNew)
{
	if (ppHead == NULL || pNew == NULL)
	{
		return;
	}

	pNew->pNext = *ppHead;
	*ppHead     = pNew;
}

/**********************************************************************************************************************/
/** Delete a secure session from the secure Queue
 *
 *  @param[in]      ppHead          pointer to pointer to head of queue
 *  @param[in]      pDelete         pointer to element to delete
 */

void    trdp_sec_queueDelSecSess (
		TRDPSEC_SECURE_SESSION_T    * *ppHead,
		TRDPSEC_SECURE_SESSION_T    *pDelete)
{
	TRDPSEC_SECURE_SESSION_T *iterSecSess;

	if (ppHead == NULL || *ppHead == NULL || pDelete == NULL)
	{
		return;
	}

	/* handle removal of first element */
	if (pDelete == *ppHead)
	{
		*ppHead = (TRDPSEC_SECURE_SESSION_T*) pDelete->pNext;
		return;
	}

	for (iterSecSess = *ppHead; iterSecSess != NULL; iterSecSess = iterSecSess->pNext)
	{
		if (iterSecSess->pNext && iterSecSess->pNext == pDelete)
		{
			iterSecSess->pNext = pDelete->pNext;
			return;
		}
	}
}

/**********************************************************************************************************************/
/** Computes the HMAC value over a whole TRDP telegram
 *
 *  @param[in]      pKey			pointer to the secret key struct
 *  @param[in]      keySize         the secret key size
 *  @param[in]     	pPacket			pointer to the TRDP packet (header + dataset)
 *  @retval         UINT32			the computed HMAC value
 */
EXT_DECL UINT32 trdp_sec_hmac (
		const void* 	pKey,
		INT32 			keySize,
		const UINT8		*pPacket,
		UINT16 			packetSize)
{
	UINT32 	hmacSize = 32;
	UINT32 	retVal;
	UINT8 	hmacVal[32];

	/* set CRC filed temporary to 0 */
	UINT32 tmpVal = ((PD_HEADER_T*)pPacket)->frameCheckSum;
	((PD_HEADER_T*)pPacket)->frameCheckSum  = 0u;

	if (pKey == NULL || pPacket == NULL || packetSize == 0 || keySize == 0)
	{
		return 0;
	}

	if (HMAC(EVP_sha3_256(),pKey, (int)keySize, (const unsigned char*)pPacket,
			(int)packetSize, (unsigned char*) hmacVal, &hmacSize) == NULL)
	{
		return 0;
	}

	/* Setting the old crc value back */
	((PD_HEADER_T*)pPacket)->frameCheckSum = tmpVal;

	retVal = ((UINT32*)hmacVal)[0];
	return retVal;
}

/**********************************************************************************************************************/
/** decripts a given ciphertext and generates a the original plaintext with the aes-256 blockcipher in CBC mode
 *
 *  @param[in]      pCiphertext				pointer to the ciphertext
 *  @param[in]      ciphertextLen         	length of the ciphertext
 *  @param[in]     	pKey					decryption key
 *  @param[in]     	pIV						pointer to the initial vector for the CBC mode
 *  @param[in]     	pPlaintext				pointer to the plaintext
 *
 *  @retval         ciphertextLen			the length of the generated ciphertext
 **/
EXT_DECL INT32 trdp_sec_decryptAes256CBC(UINT8 *pCiphertext, INT32 ciphertextLen, UINT8 *pKey,
            UINT8 *pIV, UINT8 *pPlaintext)
{
    EVP_CIPHER_CTX *pCtx;

    INT32 tmpLen;

    INT32 plaintextLen;

    /* Create and initialise the context */
    if((pCtx = EVP_CIPHER_CTX_new()) == NULL)
    {
    	/* TODO: handling e.g. return error */
    	return 0;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure the use of a key and IV size appropriate for the cipher
     * In this function:
     * 		- 256 bit AES (i.e. a 256 bit key). The
     * 		- IV size for *most* modes is the same as the block size. For AES it is 128 bits
     */
    if(EVP_DecryptInit_ex(pCtx, EVP_aes_256_cbc(), NULL, (unsigned char*) pKey, (unsigned char*) pIV) != TRUE)
    {
    	/* TODO: handling e.g. return error */
    	return 0;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(EVP_DecryptUpdate(pCtx, (unsigned char*) pPlaintext, &tmpLen, (unsigned char*) pCiphertext, (int) ciphertextLen) != TRUE)
    {
    	/* TODO: handling e.g. return error */
    	return 0;
    }
    plaintextLen = tmpLen;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(EVP_DecryptFinal_ex(pCtx, (unsigned char*) pPlaintext + tmpLen, &tmpLen) != TRUE)
    {
    	/* TODO: handling e.g. return error */
        return 0;
    }
    plaintextLen += tmpLen;

    /* Clean up */
    EVP_CIPHER_CTX_free(pCtx);

    return plaintextLen;
}

/**********************************************************************************************************************/
/** calculates a hash value based on the SHA3-256 function
 *
 *  @param[in]    	sessionSeqCnt  		handle returned also by tlc_init
 *  @param[in]    	pData       	    pointer to user context
 *  @param[in]    	pSecretDataSize		pointer to received message information
 *  @param[in]    	pHash         		pointer to received data
 *  @param[in]    	dataSize      		size of received data pointer to received data
 *
 *  @retval         digestLength		the length of the generated ciphertext
 **/
UINT32 trdp_sec_sha256(UINT32 sessionSeqCnt, UINT8 *pData, INT32 pSecretDataSize, UINT8* pHash)
{
	SHA256_CTX *pCtx;
	UINT32 digestLen = 0;

	if (SHA256_Init(pCtx) == NULL)
	{
		return digestLen;
	}

	if (SHA256_Update(pCtx, (void*) pSecretData, (int) pSecretDataSize) != TRUE)
	{
		return digestLen;
	}

	if (SHA256_Final((unsigned char*) pHash, pCtx) != TRUE)
	{
		return digestLen;
	}
	
	digestLen = SHA256_DIGEST_LENGTH;

	return digestLen;
}

/**********************************************************************************************************************/
/** The callback function, which is called when a handshake reply is received
 *
 *  @param[in]    appHandle     handle returned also by tlc_init
 *  @param[in]    pRefCon       pointer to user context
 *  @param[in]    pMsg          pointer to received message information
 *  @param[in]    pData         pointer to received data
 *  @param[in]    dataSize      size of received data pointer to received data
 */
EXT_DECL void trdp_sec_requesterCallback(
		void *                 pRefCon,
		TRDP_APP_SESSION_T     appHandle,
		const TRDP_MD_INFO_T   *pMsg,
		UINT8 *                pData,
		UINT32                 dataSize)
{
	int field_size;
	UINT16 secretLen = 64;
	CHAR8*	secret;
	EC_KEY *pPrivateKey;
	UINT8 keyRes = 0;
	EC_POINT *pPeerPublicKey;
	TRDPSEC_SECURE_SESSION_T *pSecSession = (TRDPSEC_SECURE_SESSION_T *)pMsg->pUserRef;
	EC_GROUP *plocalKeyGroup;

	BN_CTX *ctx = BN_CTX_new();
	UINT8 counter;

	if (ctx == NULL || pSecSession == NULL || pData == NULL || dataSize != TRDPSEC_PUBLIC_KEY_LENGTH)
	{
		return;
	}

	if(NULL == (pPrivateKey = EC_KEY_new_by_curve_name(NID_brainpoolP256r1)))
	{
		return;
	}

	/* Generate the private and public key */
	if(1 != EC_KEY_generate_key(pPrivateKey))
	{
		return;
	}

	keyRes = EC_KEY_oct2priv(pPrivateKey, (unsigned char*) pSecSession->privateKey, TRDPSEC_PRIVATE_KEY_LENGTH);
	if (pPrivateKey == NULL || keyRes != 1)
	{
		return;
	}

	plocalKeyGroup = EC_KEY_get0_group(pPrivateKey);
	if (plocalKeyGroup == NULL)
	{
		return;
	}

	if ((pMsg->resultCode == TRDP_NO_ERR) && (pMsg->msgType == TRDP_MSG_MP) && (pMsg->comId == TRDPSEC_HANDSHAKE_COMID))
	{
		/* Extract the peer public key from the dataset and convert it to the EC_POINT* format */
		pPeerPublicKey = EC_POINT_hex2point(plocalKeyGroup, (char *) pData, NULL, ctx);
		if (pPeerPublicKey == NULL)
		{
			return;
		}

		/* Calculate the size of the buffer for the shared secret */
		field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pPrivateKey));
		secretLen = (field_size+7)/8;
		if (secretLen == 0)
		{
			return;
		}

		/* Allocate the memory for the shared secret */
		if(NULL == (secret = OPENSSL_malloc(secretLen)))
		{
			return;
		}

		/* Derive the shared secret */
		secretLen = ECDH_compute_key(secret, secretLen, (EC_POINT*) pPeerPublicKey, pPrivateKey, NULL);
		if (secretLen == 0 || secret == NULL)
		{
			return;
		}

		/* Reserve mutual access to the communication partners queue */
		if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
		{
			return;
		}

		/* copy the shared secret into the communication partner's shared secret
		 * and set the secret key status as already exchanged.
		 * The communication partner is now set as identified */
		memcpy(pSecSession->sharedSecret, secret, secretLen);
		pSecSession->sessionStatus = TRDPSEC_VALID_SESSION;

		/* Free mutual access to the communication partners queue */
		if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
		{
			vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
			return;
		}

		printf("The new secret is: ");
		for (counter = 0; counter < 32; counter++)
		{
			printf("%02X", ((UINT8*)secret)[counter]);
		}
		printf("\n");

		/* clean */
		EC_KEY_free(pPrivateKey);
		EC_POINT_free(pPeerPublicKey);
	}
}

/**********************************************************************************************************************/
/** The callback function, which is called when a handshake request is received
 *
 *  @param[in]    appHandle     handle returned also by tlc_init
 *  @param[in]    pRefCon       pointer to user context
 *  @param[in]    pMsg          pointer to received message information
 *  @param[in]    pData         pointer to received data
 *  @param[in]    dataSize      size of received data pointer to received data
 */
EXT_DECL void trdp_sec_replierCallback(
		void *                 pRefCon,
		TRDP_APP_SESSION_T     appHandle,
		const TRDP_MD_INFO_T   *pMsg,
		UINT8 *                pData,
		UINT32                 dataSize)
{
	EC_KEY *pPrivateKey;
	EC_POINT *pPeerPublicKey, *pOwnPublicKey;
	int field_size;
	unsigned char *pSecret;
	int secret_len = TRDPSEC_SECRET_LENGTH;
	EC_GROUP *pOwnKeyGroup;
	UINT8* pOwnHexPublicKey;
	BN_CTX *ctx = BN_CTX_new();
	TRDP_ERR_T err;
	TRDPSEC_SECURE_SESSION_T *pSecHandle = (TRDPSEC_SECURE_SESSION_T*) pMsg->pUserRef;

	if (ctx == NULL || pSecHandle == NULL || pData == NULL || dataSize != TRDPSEC_PUBLIC_KEY_LENGTH)
	{
		return;
	}

	if ((pMsg->resultCode == TRDP_NO_ERR) && (pMsg->msgType == TRDP_MSG_MR) && (pMsg->comId == TRDPSEC_HANDSHAKE_COMID))
	{
		/* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
		if(NULL == (pPrivateKey = EC_KEY_new_by_curve_name(NID_brainpoolP256r1)))
		{
			return;
		}

		/* Generate the local private and public key */
		if(1 != EC_KEY_generate_key(pPrivateKey))
		{
			return;
		}

		/* Generate the local public key */
		pOwnPublicKey = EC_KEY_get0_public_key(pPrivateKey);
		if (pOwnPublicKey == NULL)
		{
			return;
		}

		/* Generate the local key group */
		pOwnKeyGroup = EC_KEY_get0_group(pPrivateKey);
		if (pOwnKeyGroup == NULL)
		{
			return;
		}

		/* Extract the local public key from the local_key structure in hex form */
		pOwnHexPublicKey = (UINT8*) EC_POINT_point2hex(pOwnKeyGroup, pOwnPublicKey, POINT_CONVERSION_UNCOMPRESSED,ctx);
		if (pOwnHexPublicKey == NULL)
		{
			return;
		}

		/* Extract the peer public key from the dataset and convert it to the EC_POINT* format */
		pPeerPublicKey = EC_POINT_hex2point(pOwnKeyGroup, (char*)pData, NULL, ctx);
		if (pPeerPublicKey == NULL)
		{
			return;
		}

		/* Calculate the size of the buffer for the shared secret */
		field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pPrivateKey));
		secret_len = (field_size+7)/8;

		if (secret_len == 0)
		{
			return;
		}

		/* Allocate the memory for the shared secret */
		if(NULL == (pSecret = OPENSSL_malloc(secret_len)))
		{
			return;
		}
		/* Derive the shared secret */
		secret_len = ECDH_compute_key(pSecret, secret_len, pPeerPublicKey, pPrivateKey, NULL);
		if (secret_len == 0 || pSecret == NULL)
		{
			return;
		}

		/* Reserve mutual access to the communication partners queue */
		if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
		{
			return;
		}

		memcpy(pSecHandle->sharedSecret, pSecret, secret_len);
		pSecHandle->sessionStatus = TRDPSEC_VALID_SESSION;

		/* Free mutual access to the communication partners queue */
		if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
		{
			vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
			return;
		}

		/* Now we send our local private key to the peer */
		err = tlm_reply(appHandle,				/* AppHandle        */
				&pMsg->sessionId,    			/* Session ID       */
				TRDPSEC_HANDSHAKE_COMID,       	/* comID            */
				TRDP_REPLY_OK,         			/* Reply Status     */
				NULL,                   		/* Send Parameters  */
				pOwnHexPublicKey,      			/* Reply Dataset    */
				TRDPSEC_PUBLIC_KEY_LENGTH,		/* Reply Datasize   */
				NULL); 							/* Source URI	    */

		if (err != TRDP_NO_ERR)
		{
			return;
		}

		/* Clean up */
		OPENSSL_free(pOwnHexPublicKey);
		EC_KEY_free(pPrivateKey);
	}
}

/**********************************************************************************************************************/
/** Initiate the handshake by a given IP address
 *
 *  @param[in]      appHandle       				session pointer
 *  @param[in]      srcIpAddr          				The local IP address
 *  @param[in]      destIpAddr      				The peer IP address
 *  @param[in]     	timeout							timeout for the handshake
 *  @retval         != TRDPSEC_NO_ERR  		error
 */
EXT_DECL TRDP_ERR_T trdp_sec_handshakeByAddr(
		TRDP_APP_SESSION_T 		appHandle,
		TRDP_IP_ADDR_T 			srcIpAddr,
		TRDP_IP_ADDR_T 			destIpAddr,
		UINT32 					timeout)
{
	TRDP_ERR_T err = TRDP_NO_ERR;
	TRDP_UUID_T sessionId;
	EC_KEY *pPrivateKey;
	CHAR8 hexPrivateKey[TRDPSEC_PRIVATE_KEY_LENGTH];
	UINT16 hexPrivateKeyLen = TRDPSEC_PRIVATE_KEY_LENGTH;
	EC_POINT *pOwnPublicKey;
	CHAR8 *pPeerHexPublicKey;
	EC_GROUP *pOwnKeyGroup;
	BN_CTX *ctx = BN_CTX_new();
	TRDPSEC_SECURE_SESSION_T *pSecHandle = NULL;

	/* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
	if(NULL == (pPrivateKey = EC_KEY_new_by_curve_name(NID_brainpoolP256r1)))
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Generate the private and public key */
	if(1 != EC_KEY_generate_key(pPrivateKey))
	{
		return TRDP_SEC_KEY_ERR;
	}

	hexPrivateKeyLen = (UINT16) EC_KEY_priv2oct(pPrivateKey, (unsigned char*)hexPrivateKey, TRDPSEC_PRIVATE_KEY_LENGTH);
	if (hexPrivateKeyLen != TRDPSEC_PRIVATE_KEY_LENGTH)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Reserve mutual access to the secure sessions queue */
	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		return TRDP_MEM_ERR;
	}
	/* find the corresponding communication partner */
	trdp_sec_queueFindSecSession(appHandle, destIpAddr, &pSecHandle);
	if (pSecHandle == NULL)
	{
		return TRDP_SEC_NOSESSION_ERR;
	}

	memcpy(pSecHandle->privateKey, hexPrivateKey, TRDPSEC_PRIVATE_KEY_LENGTH);

	if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
	}

	/* Generate the local public key */
	pOwnPublicKey = EC_KEY_get0_public_key(pPrivateKey);
	if (pOwnPublicKey == NULL)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Generate the local key group */
	pOwnKeyGroup = EC_KEY_get0_group(pPrivateKey);
	if (pOwnKeyGroup == NULL)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Extract the local public key from the local_key structure in hex form */
	pPeerHexPublicKey = EC_POINT_point2hex(pOwnKeyGroup, pOwnPublicKey, POINT_CONVERSION_UNCOMPRESSED,ctx);
	if (pPeerHexPublicKey == NULL)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Now we send our local private key to the peer */
	err = tlm_request(appHandle,
			(void *)pSecHandle,
			(TRDP_MD_CALLBACK_T) trdp_sec_requesterCallback,
			&sessionId,
			TRDPSEC_HANDSHAKE_COMID,
			0u,
			0u,
			srcIpAddr,
			destIpAddr,
			TRDP_FLAGS_CALLBACK,
			1u, timeout,
			NULL,
			(UINT8*)pPeerHexPublicKey,
			TRDPSEC_PUBLIC_KEY_LENGTH,
			NULL,
			NULL);

	if (err != TRDP_NO_ERR)
	{
		printf("trdp_request() on comId %d", TRDPSEC_HANDSHAKE_COMID);
		return TRDP_SEC_KEY_SEND_ERR;
	}

	return TRDP_NO_ERR;
}

/**********************************************************************************************************************/
/** Receive MD packet transmitted via TCP
 *
 *  @param[in]      appHandle       session pointer
 *  @param[in]      mdSock          socket descriptor
 *  @param[out]     pElement        pointer to received packet
 *  @retval         != TRDP_NO_ERR  error
 */
EXT_DECL TRDP_ERR_T trdp_sec_initiateHandshake(
		TRDP_APP_SESSION_T 			appHandle,
		TRDPSEC_SECURE_SESSION_T 	*pSecHandle,
		UINT32 						timeout)
{
	TRDP_ERR_T err = TRDP_NO_ERR;
	TRDP_UUID_T sessionId;
	EC_KEY *pPrivateKey;
	CHAR8 hexPrivateKey[TRDPSEC_PRIVATE_KEY_LENGTH];
	UINT16 hexPrivateKeyLen = TRDPSEC_PRIVATE_KEY_LENGTH;
	EC_POINT *pOwnPublicKey;
	UINT8 *pPeerHexPublicKey;
	EC_GROUP *pOwnKeyGroup;
	BN_CTX *ctx = BN_CTX_new();

	if (pSecHandle == NULL)
	{
		return TRDP_PARAM_ERR;
	}

	/* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
	if(NULL == (pPrivateKey = EC_KEY_new_by_curve_name(NID_brainpoolP256r1)))
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Generate the private and public key */
	if(1 != EC_KEY_generate_key(pPrivateKey))
	{
		return TRDP_SEC_KEY_ERR;
	}

	hexPrivateKeyLen = (UINT16) EC_KEY_priv2oct(pPrivateKey, (unsigned char*)hexPrivateKey, TRDPSEC_PRIVATE_KEY_LENGTH);
	if (hexPrivateKeyLen != TRDPSEC_PRIVATE_KEY_LENGTH)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/*    Reserve mutual access    */
	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		return TRDP_MUTEX_ERR;
	}

	memcpy(pSecHandle->privateKey, hexPrivateKey, TRDPSEC_PRIVATE_KEY_LENGTH);

	if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
	}

	/* Generate the local public key */
	pOwnPublicKey = EC_KEY_get0_public_key(pPrivateKey);
	if (pOwnPublicKey == NULL)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Generate the local key group */
	pOwnKeyGroup = EC_KEY_get0_group(pPrivateKey);
	if (pOwnKeyGroup == NULL)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Extract the local public key from the local_key structure in hex form */
	pPeerHexPublicKey = (UINT8 *) EC_POINT_point2hex(pOwnKeyGroup, pOwnPublicKey, POINT_CONVERSION_UNCOMPRESSED,ctx);
	if (pPeerHexPublicKey == NULL)
	{
		return TRDP_SEC_KEY_ERR;
	}

	/* Now we send our local private key to the peer */
	err = tlm_request(appHandle,
			(void *)pSecHandle,
			(TRDP_MD_CALLBACK_T) trdp_sec_requesterCallback,
			&sessionId,
			TRDPSEC_HANDSHAKE_COMID,
			0u,
			0u,
			appHandle->realIP,
			pSecHandle->addr,
			TRDP_FLAGS_CALLBACK,
			1, timeout,
			NULL,
			pPeerHexPublicKey,
			TRDPSEC_PUBLIC_KEY_LENGTH,
			NULL,
			NULL);

	if (err != TRDP_NO_ERR)
	{
		printf("trdp_request() on comId %d", TRDPSEC_HANDSHAKE_COMID);
		return TRDP_SEC_KEY_SEND_ERR;
	}

	OPENSSL_free(pPeerHexPublicKey);
	EC_KEY_free(pPrivateKey);

	return TRDP_NO_ERR;
}

/**********************************************************************************************************************/
/** Subscribe to MD messages with a specific comId.
 *  Add this listener to receive the incoming handshake requests
 *
 *  @param[in]      appHandle           the handle returned by tlc_openSession
 *  @param[out]     pListenHandle       Handle for this listener returned
 *  @param[in]      pUserRef            user supplied value returned with received message
 *  @param[in]      pfCbFunction        Pointer to listener specific callback function, NULL to use default function
 *  @param[in]      comIdListener       set TRUE if comId shall be observed
 *  @param[in]      comId               comId to be observed
 *  @param[in]      etbTopoCnt          ETB topocount to use, 0 if consist local communication
 *  @param[in]      opTrnTopoCnt        operational topocount, != 0 for orientation/direction sensitive communication
 *  @param[in]      srcIpAddr1          Source IP address, lower address in case of address range, set to 0 if not used
 *  @param[in]      srcIpAddr2          upper address in case of address range, set to 0 if not used
 *  @param[in]      mcDestIpAddr        multicast group to listen on
 *  @param[in]      pktFlags            OPTION: TRDP_FLAGS_DEFAULT, TRDP_FLAGS_MARSHALL
 *  @param[in]      srcURI              only functional group of source URI, set to NULL if not used
 *  @param[in]      destURI             only functional group of destination URI, set to NULL if not used

 *  @retval         TRDP_NO_ERR         no error
 *  @retval         TRDP_PARAM_ERR      parameter error
 *  @retval         TRDP_MEM_ERR        out of memory
 *  @retval         TRDP_NOINIT_ERR     handle invalid
 */
EXT_DECL TRDP_ERR_T trdp_sec_addHandshakeListener(
		TRDP_APP_SESSION_T		appHandle,
		TRDP_IP_ADDR_T          srcIpAddr)
{
	TRDP_LIS_T listener;
	TRDP_ERR_T err = TRDP_NO_ERR;
	TRDPSEC_HDSHAKE_REP_CB_T test_cb = {TRDP_NO_ERR, 0};

	if (!trdp_isValidSession(appHandle))
	{
		return TRDP_MEM_ERR;
	}

	err = tlm_addListener(
			appHandle,										/* appHandle                        */
			&listener,             							/* listenerHandle                   */
			(void *)&test_cb,        						/* pointer to user supplied values  */
			(TRDP_MD_CALLBACK_T) trdp_sec_replierCallback, 	/* callback function                */
			TRUE,                      						/* comID shall be observed          */
			TRDPSEC_HANDSHAKE_COMID,                		/* comID                            */
			0u,                        						/* etbTopoCnt                       */
			0u,                        						/* opTrnTopoCnt                     */
			srcIpAddr,     									/* srcIpAddr1                       */
			0u,                        						/* srcIpAddr2                       */
			0u,                        						/* multiCast Destination IP         */
			TRDP_FLAGS_CALLBACK,       						/* flags                            */
			NULL,                      						/* source URI                       */
			NULL);                     						/* destination URI                  */
	if (err != TRDP_NO_ERR)
	{
		printf("nt_tim_addListener() on comId %d", TRDPSEC_HANDSHAKE_COMID);
	}

	return err;
}

/**********************************************************************************************************************/
/** Subscribe to MD messages with a specific comId.
 *  Add this listener to receive the incoming handshake requests
 *
 *  @param[in]      appHandle           the handle returned by tlc_openSession
 *  @param[out]     pListenHandle       Handle for this listener returned
 *  @param[in]      pUserRef            user supplied value returned with received message
 *  @param[in]      pfCbFunction        Pointer to listener specific callback function, NULL to use default function
 *  @param[in]      comIdListener       set TRUE if comId shall be observed
 *  @param[in]      comId               comId to be observed
 *  @param[in]      etbTopoCnt          ETB topocount to use, 0 if consist local communication
 *  @param[in]      opTrnTopoCnt        operational topocount, != 0 for orientation/direction sensitive communication
 *  @param[in]      srcIpAddr1          Source IP address, lower address in case of address range, set to 0 if not used
 *  @param[in]      srcIpAddr2          upper address in case of address range, set to 0 if not used
 *  @param[in]      mcDestIpAddr        multicast group to listen on
 *  @param[in]      pktFlags            OPTION: TRDP_FLAGS_DEFAULT, TRDP_FLAGS_MARSHALL
 *  @param[in]      srcURI              only functional group of source URI, set to NULL if not used
 *  @param[in]      destURI             only functional group of destination URI, set to NULL if not used

 *  @retval         TRDP_NO_ERR         no error
 *  @retval         TRDP_PARAM_ERR      parameter error
 *  @retval         TRDP_MEM_ERR        out of memory
 *  @retval         TRDP_NOINIT_ERR     handle invalid
 */
EXT_DECL TRDP_ERR_T trdp_sec_addHandshakeListenerBySess(
		TRDP_APP_SESSION_T			appHandle,
		TRDPSEC_SECURE_SESSION_T 	*pSecHandle)
{
	TRDP_LIS_T listener;
	TRDP_ERR_T err = TRDP_NO_ERR;

	if (!trdp_isValidSession(appHandle) || pSecHandle == NULL)
	{
		return TRDP_MEM_ERR;
	}

	err = tlm_addListener(
			appHandle,										/* appHandle                        */
			&listener,             							/* listenerHandle                   */
			(void *)pSecHandle,        						/* pointer to user supplied values  */
			(TRDP_MD_CALLBACK_T) trdp_sec_replierCallback, 	/* callback function                */
			TRUE,                      						/* comID shall be observed          */
			TRDPSEC_HANDSHAKE_COMID,          				/* comID                            */
			0u,                        						/* etbTopoCnt                       */
			0u,                        						/* opTrnTopoCnt                     */
			pSecHandle->addr,								/* srcIpAddr1                       */
			0u,                        						/* srcIpAddr2                       */
			0u,                        						/* multiCast Destination IP         */
			TRDP_FLAGS_CALLBACK,       						/* flags                            */
			NULL,                      						/* source URI                       */
			NULL);                     						/* destination URI                  */
	if (err != TRDP_NO_ERR)
	{
		printf("nt_tim_addListener() on comId %d", TRDPSEC_HANDSHAKE_COMID);
	}

	return err;
}

/**********************************************************************************************************************/
/** Check if the PD header values and the CRCs are sane
 *
 *  @param[in]      pPacket         pointer to the packet to check
 *  @param[in]      packetSize      max size to check
 *  @param[in]     	pPDElem         the corresponding PD element to the received telegram
 *  @param[out]     pIsTSN          set to TRUE on return if PD2 frame
 *
 *  @retval         TRDP_NO_ERR
 *  @retval         TRDP_CRC_ERR
 */
EXT_DECL TRDP_ERR_T trdp_sec_pdCheck (
		PD_HEADER_T *pPacket,
		UINT32      packetSize,
		PD_ELE_T	*pPDElem,
		int         *pIsTSN)
{
	UINT32 	myHMAC = 0;
	TRDP_ERR_T      err = TRDP_NO_ERR;

#ifdef TSN_SUPPORT
	PD2_HEADER_T    *pPacket2 = (PD2_HEADER_T *) pPacket;

	/*  Check for TSN small header first    */
	if (pPacket2->protocolVersion == 0x2)
	{
		*pIsTSN = TRUE;
		if ((packetSize < TRDP_MIN_PD2_HEADER_SIZE) ||
				(packetSize > TRDP_MAX_PD2_PACKET_SIZE))
		{
			vos_printLog(VOS_LOG_INFO, "PDframe size error (%u))\n", packetSize);
			err = TRDP_WIRE_ERR;
		}
		else
		{
			if (pPDElem->mustBeSecure == TRUE)
			{
				if (pPDElem->pSecElem != NULL && pPDElem->pSecElem->sharedSecretStatus == TRDPSEC_SECRET_EXCHANGED &&
						pPDElem->pSecElem->sharedSecret != NULL)
				{
					myHMAC = trdp_sec_hmac(pPDElem->pSecElem->sharedSecret, TRDPSEC_SECRET_LENGTH,
							(UINT8 *) pPacket, (UINT16)(UINT16)packetSize);
				}
			}

			if (pPacket->frameCheckSum != MAKE_LE(myHMAC))
			{
				vos_printLog(VOS_LOG_INFO, "PDframe hmac error (%08x != %08x))\n", pPacket->frameCheckSum, MAKE_LE(myHMAC));
				err = TRDP_CRC_ERR;
			}

			/*  Check type  */
			else if ((pPacket2->msgType != TRDP_MSG_TSN_PD) &&
					(pPacket2->msgType != TRDP_MSG_TSN_PD_SDT) &&
					(pPacket2->msgType != TRDP_MSG_TSN_PD_MSDT) &&
					(pPacket2->msgType != TRDP_MSG_TSN_PD_RES))
			{
				vos_printLog(VOS_LOG_INFO, "PDframe type error, received %02x\n", pPacket2->msgType);
				err = TRDP_WIRE_ERR;
			}
			/*  Check size  */
			else if (vos_ntohs(pPacket2->datasetLength) > TRDP_MAX_PD2_DATA_SIZE)
			{
				vos_printLog(VOS_LOG_INFO, "PDframe datalength error, received %04x\n", pPacket2->msgType);
				err = TRDP_WIRE_ERR;
			}
		}
	}
	else
#endif
	{   /* Version 1 TRDP (non-TSN) */
		*pIsTSN = FALSE;
		/*  Check size    */
		if ((packetSize < TRDP_MIN_PD_HEADER_SIZE) ||
				(packetSize > TRDP_MAX_PD_PACKET_SIZE))
		{
			vos_printLog(VOS_LOG_INFO, "PDframe size error (%u))\n", packetSize);
			err = TRDP_WIRE_ERR;
		}
		else
		{
			if (pPDElem->mustBeSecure == TRUE)
			{
				if (pPDElem->pSecSession != NULL && pPDElem->pSecSession->sessionStatus == TRDPSEC_VALID_SESSION &&
						pPDElem->pSecSession->sharedSecret != NULL)
				{
					myHMAC = trdp_sec_hmac(pPDElem->pSecSession->sharedSecret, TRDPSEC_SECRET_LENGTH,
							(UINT8 *) pPacket, (UINT16)packetSize);
				}
			}

			if (pPacket->frameCheckSum != MAKE_LE(myHMAC))
			{
				vos_printLog(VOS_LOG_INFO, "PDframe hmac error (%08x != %08x))\n", pPacket->frameCheckSum, MAKE_LE(myHMAC));
				err = TRDP_CRC_ERR;
			}

			/*  Check protocol version  */
			else if (((vos_ntohs(pPacket->protocolVersion) & TRDP_PROTOCOL_VERSION_CHECK_MASK)
					!= (TRDP_PROTO_VER & TRDP_PROTOCOL_VERSION_CHECK_MASK)) ||
					(vos_ntohl(pPacket->datasetLength) > TRDP_MAX_PD_DATA_SIZE))
			{
				vos_printLog(VOS_LOG_INFO, "PDframe protocol error (%04x != %04x))\n",
						vos_ntohs(pPacket->protocolVersion),
						TRDP_PROTO_VER);
				err = TRDP_WIRE_ERR;
			}
			/*  Check type  */
			else if ((vos_ntohs(pPacket->msgType) != (UINT16) TRDP_MSG_PD) &&
					(vos_ntohs(pPacket->msgType) != (UINT16) TRDP_MSG_PP) &&
					(vos_ntohs(pPacket->msgType) != (UINT16) TRDP_MSG_PR) &&
					(vos_ntohs(pPacket->msgType) != (UINT16) TRDP_MSG_PE))
			{
				vos_printLog(VOS_LOG_INFO, "PDframe type error, received %04x\n", vos_ntohs(pPacket->msgType));
				err = TRDP_WIRE_ERR;
			}
		}
		return err;
	}
}
