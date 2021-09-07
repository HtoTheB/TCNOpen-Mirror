/**********************************************************************************************************************/
/**
 * @file            tau_sec.c
 *
 * @brief           API implementation for TRDP secure communication
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSec prototype stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * $Id: tau_sec.c 2309 2021-09-07 11:56:44Z mohamedyoussef $
 */

/***********************************************************************************************************************
 * INCLUDES
 */

#include "tau_sec.h"
#include "trdp_sec_types.h"
#include "trdp_sec_utils.h"
#include "trdp_utils.h"
#include "tlc_if.h"
#include "trdp_pdcom.h"
#include "string.h"
#include <openssl/evp.h>
#include <openssl/ec.h>

/***********************************************************************************************************************
 * TYPEDEFS
 */

/***********************************************************************************************************************
 * LOCALS
 */

/***********************************************************************************************************************
 * LOCAL FUNCTIONS
 */

/**********************************************************************************************************************/
/** Prepare for sending PD secure messages.
 * 	Add a new secure session and perform a handshake with the corresponding secure peer
 *  If the handshake was successfull the queue the PD message, it will be send when tlc_publish has been called
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pPubHandle          		returned handle for related re/unpublish
 *  @param[in]      pUserRef            		user supplied value returned within the info structure of
 *  											callback function
 *  @param[in]      pfCbFunction        		Pointer to pre-send callback function, NULL if not used
 *  @param[in]      serviceId           		optional serviceId this telegram belongs to (default = 0)
 *  @param[in]      comId               		comId of packet to send
 *  @param[in]      etbTopoCnt          		ETB topocount to use, 0 if consist local communication
 *  @param[in]      opTrnTopoCnt        		operational topocount, != 0 for orientation/direction
 *  											sensitive communication
 *  @param[in]      srcIpAddr           		own IP address, 0 - srcIP will be set by the stack
 *  @param[in]      destIpAddr          		where to send the packet to
 *  @param[in]      interval            		frequency of PD packet (>= 10ms) in usec
 *  @param[in]      redId               		0 - Non-redundant, > 0 valid redundancy group
 *  @param[in]      pktFlags            		OPTION:
 *                                      		TRDP_FLAGS_DEFAULT, TRDP_FLAGS_NONE, TRDP_FLAGS_MARSHALL,
 *                                      		TRDP_FLAGS_CALLBACK
 *  @param[in]      pSendParam          		optional pointer to send parameter, NULL - default parameters are used
 *  @param[in]      pData               		optional pointer to data packet / dataset, NULL if sending
 *  											starts later with tlp_put()
 *  @param[in]      dataSize            		size of data packet >= 0 and <= TRDP_MAX_PD_DATA_SIZE
 *  @param[in]		timeout						timeout to receive the handshake reply message
 *
 *  @retval         TRDP_NO_ERR         		no error
 *  @retval         TRDP_PARAM_ERR      		parameter error
 *  @retval         TRDP_MEM_ERR        		could not insert (out of memory)
 *  @retval         TRDP_NOINIT_ERR     		handle invalid
 *  @retval			TRDP_SEC_NOSESSION_ERR		could not create a secure session
 *  @retval			TRDP_SEC_HANDSHAKE_ERR		could not perform a handshake
 */
EXT_DECL TRDP_ERR_T tau_sec_publish (
		TRDP_APP_SESSION_T      appHandle,
		TRDP_PUB_T              *pPubHandle,
		const void              *pUserRef,
		TRDP_PD_CALLBACK_T      pfCbFunction,
		UINT32                  serviceId,
		UINT32                  comId,
		UINT32                  etbTopoCnt,
		UINT32                  opTrnTopoCnt,
		TRDP_IP_ADDR_T          srcIpAddr,
		TRDP_IP_ADDR_T          destIpAddr,
		UINT32                  interval,
		UINT32                  redId,
		TRDP_FLAGS_T            pktFlags,
		const TRDP_SEND_PARAM_T *pSendParam,
		const UINT8             *pData,
		UINT32                  dataSize,
		UINT32					timeout)
{
	PD_ELE_T            *pNewElement = NULL;
	TRDP_TIME_T         nextTime;
	TRDP_TIME_T         tv_interval;
	TRDP_ERR_T          ret         = TRDP_NO_ERR;
	TRDP_MSG_T          msgType     = TRDP_MSG_PD;
	TRDP_SOCK_TYPE_T    sockType    = TRDP_SOCK_PD;

	TRDPSEC_SECURE_SESSION_T *pSecHandle;


	/*    Check params    */
	if ((interval != 0u && interval < TRDP_TIMER_GRANULARITY)
			|| (pPubHandle == NULL) ||
			/* TODO: remove when the PD multicast implementation is covered */
			vos_isMulticast(destIpAddr))
	{
		return TRDP_PARAM_ERR;
	}

	if (!trdp_isValidSession(appHandle))
	{
		return TRDP_NOINIT_ERR;
	}

	/*    Reserve mutual access    */
	ret = (TRDP_ERR_T) vos_mutexLock(appHandle->mutexTxPD);
	if (ret == TRDP_NO_ERR)
	{
		TRDP_ADDRESSES_T pubHandle;

		/* Ticket #171: srcIP should be set if there are more than one interface */
		if (srcIpAddr == VOS_INADDR_ANY)
		{
			srcIpAddr = appHandle->realIP;
		}

		/* initialize pubHandle */
		pubHandle.comId         = comId;
		pubHandle.destIpAddr    = destIpAddr;
		/* TODO: in the actual PD unicast version we do not support multicast! will follow in further versions*/
		/* pubHandle.mcGroup       = vos_isMulticast(destIpAddr) ? destIpAddr : 0u; */
		pubHandle.mcGroup       = 0u;
		pubHandle.srcIpAddr     = srcIpAddr;
		pubHandle.serviceId     = serviceId;

		/*    Look for existing element    */
		if (trdp_queueFindPubAddr(appHandle->pSndQueue, &pubHandle) != NULL)
		{
			/*  Already published! */
			ret = TRDP_NOPUB_ERR;
		}
		else
		{
			/* After verifying that there is no such a publisher, the creation of the secure session and
			 * the handshake proceedure can be done */
			pSecHandle = trdp_sec_addSecSession(appHandle, destIpAddr, 0u);
			if (pSecHandle == NULL)
			{
				return TRDP_SEC_NOSESSION_ERR;
			}

			ret = trdp_sec_initiateHandshake(appHandle, pSecHandle, timeout);
			if (ret != TRDP_NO_ERR)
			{
				return TRDP_SEC_HANDSHAKE_ERR;
			}

			pNewElement = (PD_ELE_T *) vos_memAlloc(sizeof(PD_ELE_T));
			if (pNewElement == NULL)
			{
				ret = TRDP_MEM_ERR;
			}
			else
			{
				const TRDP_SEND_PARAM_T *pCurrentSendParams = (pSendParam != NULL) ?
						pSendParam :
						&appHandle->pdDefault.sendParam;

				pNewElement->pktFlags = (pktFlags == TRDP_FLAGS_DEFAULT) ? appHandle->pdDefault.flags : pktFlags;
				/* add pointer to the corresponding secure session and set the publisher as secure one */
				pNewElement->mustBeSecure = TRUE;
				pNewElement->pSecSession = pSecHandle;

				/* mark data as invalid, data will be set valid with tlp_put */
				pNewElement->privFlags  |= TRDP_INVALID_DATA;
				pNewElement->dataSize   = dataSize;

#ifdef TSN_SUPPORT
				/* check for TSN and select the right message and socket type */
				if (pCurrentSendParams->tsn == FALSE)
				{
					/*
                     Compute the overal packet size
					 */
					pNewElement->grossSize = trdp_packetSizePD(dataSize);
				}
				else if ((pNewElement->pktFlags & (TRDP_FLAGS_TSN | TRDP_FLAGS_TSN_SDT | TRDP_FLAGS_TSN_MSDT)))
				{
					if (pCurrentSendParams->tsn == FALSE)
					{
						ret = TRDP_PARAM_ERR;
					}
					if (pNewElement->pktFlags & TRDP_FLAGS_TSN_SDT)
					{
						msgType = TRDP_MSG_TSN_PD_SDT;
					}
					else if (pNewElement->pktFlags & TRDP_FLAGS_TSN_MSDT)
					{
						msgType = TRDP_MSG_TSN_PD_MSDT;
					}
					else
					{
						msgType = TRDP_MSG_TSN_PD;
					}
					interval    = 0u;       /* force zero interval */
					sockType    = TRDP_SOCK_PD_TSN;
					pNewElement->privFlags  |= TRDP_IS_TSN;
					pNewElement->grossSize  = trdp_packetSizePD2(dataSize);
				}
				else
				{
					vos_printLogStr(VOS_LOG_ERROR, "Publish: Wrong send parameters for TSN!\n");
					ret = TRDP_PARAM_ERR;
				}
#else
				/*
                 Compute the overal packet size
				 */
				pNewElement->grossSize = trdp_packetSizePD(dataSize);
#endif
				if (ret == TRDP_NO_ERR)
				{
					/*    Get a socket    */
					ret = trdp_requestSocket(
							appHandle->ifacePD,
							appHandle->pdDefault.port,
							pCurrentSendParams,
							srcIpAddr,
							0u,
							sockType,
							appHandle->option,
							FALSE,
							-1,
							&pNewElement->socketIdx,
							0u);
				}
				/* If we couldn't get a socket, we release the used memory and exit */
				if (ret != TRDP_NO_ERR)
				{
					vos_memFree(pNewElement);
					pNewElement = NULL;
				}
				else
				{
					/*  Alloc the corresponding data buffer  */
					pNewElement->pFrame = (PD_PACKET_T *) vos_memAlloc(pNewElement->grossSize);
					if (pNewElement->pFrame == NULL)
					{
						vos_memFree(pNewElement);
						pNewElement = NULL;
						ret = TRDP_MEM_ERR;
					}
				}
			}
		}

		/*    Get the current time and compute the next time this packet should be sent.    */
		if ((ret == TRDP_NO_ERR)
				&& (pNewElement != NULL))
		{
			/*    Update the internal data */
			pNewElement->addr = pubHandle;
			pNewElement->pullIpAddress  = 0u;
			pNewElement->redId          = redId;
			pNewElement->pCachedDS      = NULL;
			pNewElement->magic          = TRDP_MAGIC_PUB_HNDL_VALUE;
			pNewElement->pUserRef       = pUserRef;

			/* PD PULL or TSN?    Packet will be sent on request only    */
			if (0 == interval)       /* Disable interval sending of TSN packets */
			{
				vos_clearTime(&pNewElement->interval);
				vos_clearTime(&pNewElement->timeToGo);
			}
			else
			{
				vos_getTime(&nextTime);
				tv_interval.tv_sec  = interval / 1000000u;
				tv_interval.tv_usec = interval % 1000000;
				vos_addTime(&nextTime, &tv_interval);
				pNewElement->interval   = tv_interval;
				pNewElement->timeToGo   = nextTime;
			}


			/* if default flags supplied and no callback func supplied, take default one */
			if ((pktFlags == TRDP_FLAGS_DEFAULT) &&
					(pfCbFunction == NULL))
			{
				pNewElement->pfCbFunction = appHandle->pdDefault.pfCbFunction;
			}
			else
			{
				pNewElement->pfCbFunction = pfCbFunction;
			}

			/*  Find a possible redundant entry in one of the other sessions and sync the sequence counter!
             curSeqCnt holds the last sent sequence counter, therefore set the value initially to -1,
             it will be incremented when sending...    */

			pNewElement->curSeqCnt = 0xFFFFFFFFu;

			/*  Get a second sequence counter in case this packet is requested as PULL. This way we will not
             disturb the monotonic sequence for PDs  */
			pNewElement->curSeqCnt4Pull = 0xFFFFFFFFu;

			/*    Check if the redundancy group is already set as follower; if set, we need to mark this one also!
             This will only happen, if publish() is called while we are in redundant mode */
			if (0 != redId)
			{
				BOOL8 isLeader = TRUE;

				ret = tlp_getRedundant(appHandle, redId, &isLeader);
				if (ret == TRDP_NO_ERR && FALSE == isLeader)
				{
					pNewElement->privFlags |= TRDP_REDUNDANT;
				}
			}

			/*    Compute the header fields */
			trdp_pdInit(pNewElement, msgType, etbTopoCnt, opTrnTopoCnt, 0u, 0u, serviceId);

#ifdef HIGH_PERF_INDEXED
			/*    Keep queue sorted    */
			trdp_queueInsThroughputAccending(&appHandle->pSndQueue, pNewElement);
#else
			/*    Insert at front    */
			trdp_queueInsFirst(&appHandle->pSndQueue, pNewElement);
#endif

			*pPubHandle = (TRDP_PUB_T) pNewElement;

#ifdef TSN_SUPPORT
			if (pNewElement->privFlags & TRDP_IS_TSN)
			{
				/* We set the vlan IP as we bound the socket to */
				pNewElement->addr.srcIpAddr = appHandle->ifacePD[pNewElement->socketIdx].bindAddr;
			}
			else
#endif
			{   /* We do not prepare data for TSN, skip this and also no need for distributing the schedules */
				if (dataSize != 0u)
				{
					ret = tlp_put(appHandle, *pPubHandle, pData, dataSize);
				}
#ifndef HIGH_PERF_INDEXED
				if ((ret == TRDP_NO_ERR) && (appHandle->option & TRDP_OPTION_TRAFFIC_SHAPING))
				{
					ret = trdp_pdDistribute(appHandle->pSndQueue);
				}
#endif
			}
		}

		if (vos_mutexUnlock(appHandle->mutexTxPD) != VOS_NO_ERR)
		{
			vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
		}
	}

	return ret;
}

/**********************************************************************************************************************/
/** reinitialize the secure session related to this publisher
 *  the corresponding secure session be invalidated, a handshake takes place before the session is
 *  reset as valid
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pPubHandle          		the publisher pointing to the secure session
 *  @param[in]		timeout						timeout to receive the handshake reply message
 *
 *  @retval         TRDP_NO_ERR         		no error
 *  @retval         TRDP_PARAM_ERR      		parameter error
 *  @retval         TRDP_MUTEX_ERR        		mutex error
 *  @retval			TRDP_SEC_KEY_ERR			key generation error
 *  @retval			TRDP_SEC_NOSESSION_ERR		no corresponding secure session has been found
 *  @retval			TRDP_SEC_KEY_SEND_ERR		own public key could not be sent to the communication peer
 */
EXT_DECL TRDP_ERR_T tau_sec_resetSecureSession(
		TRDP_APP_SESSION_T		appHandle,
		TRDP_PUB_T 				pPubHandle,
		UINT32					timeout)
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

	if (!trdp_isValidSession(appHandle) || pPubHandle == NULL || vos_isMulticast(pPubHandle->addr.destIpAddr))
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

	/* Reserve mutual access to the secure sessions queue */
	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		return TRDP_MUTEX_ERR;
	}
	/* find the corresponding communication partner */
	trdp_sec_queueFindSecSession(appHandle, pPubHandle->addr.destIpAddr, &pSecHandle);
	if (pSecHandle == NULL)
	{
		return TRDP_SEC_NOSESSION_ERR;
	}

	memcpy(pSecHandle->privateKey, hexPrivateKey, TRDPSEC_PRIVATE_KEY_LENGTH);

	if (vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
		return TRDP_MUTEX_ERR;
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
			pPubHandle->addr.srcIpAddr,
			pPubHandle->addr.destIpAddr,
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
/** deactivate the secure session related to this subscriber
 *  the corresponding secure session is deleted and the publisher is set as non secure
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pPubHandle          		returned publish handle for related invalid secure session

 *  @retval         TRDP_NO_ERR         		no error
 *  @retval         TRDP_PARAM_ERR      		parameter error
 *  @retval         TRDP_MUTEX_ERR      		mutex error
 */
EXT_DECL TRDP_ERR_T tau_sec_invalidPubSecureSession(
		TRDP_APP_SESSION_T		appHandle,
		TRDP_PUB_T 				pPubHandle)
{
	if (!trdp_isValidSession(appHandle) || pPubHandle == NULL || pPubHandle->pSecSession == NULL)
	{
		return TRDP_PARAM_ERR;
	}

	/* Reserve mutual access to the secure sessions queue and the publisher queue */
	if (vos_mutexLock(appHandle->mutexTxPD) != VOS_NO_ERR)
	{
		return TRDP_MUTEX_ERR;
	}

	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		/* if the mutexSecSessQueue cannot be locked then we must unlock the mutexTxPD and return the error */
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexLock() failed\n");
		if (vos_mutexUnlock(appHandle->mutexTxPD) != VOS_NO_ERR)
		{
			vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
		}
		return TRDP_MUTEX_ERR;
	}

	trdp_sec_queueDelSecSess(&appHandle->pSecQueue, pPubHandle->pSecSession);
	pPubHandle->mustBeSecure = FALSE;
	vos_memFree(pPubHandle->pSecSession);
	pPubHandle->pSecSession = NULL;

	if ((vos_mutexUnlock(appHandle->mutexTxPD) != VOS_NO_ERR) ||
			(vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR))
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
		return TRDP_MUTEX_ERR;
	}

	return TRDP_NO_ERR;
}

/**********************************************************************************************************************/
/** Prepare for receiving secure PD messages.
 *  Add the corresponding secure session and a handshake listener to catch handshake requests
 *  Subscribe to a specific PD ComID and source IP.
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pSubHandle          		return a handle for this subscription
 *  @param[in]      pUserRef            		user supplied value returned within the info structure
 *  @param[in]      pfCbFunction        		Pointer to subscriber specific callback function, NULL to
 *  											use default function
 *  @param[in]      serviceId           		optional serviceId this telegram belongs to (default = 0)
 *  @param[in]      comId               		comId of packet to receive
 *  @param[in]      etbTopoCnt          		ETB topocount to use, 0 if consist local communication
 *  @param[in]      opTrnTopoCnt        		operational topocount, != 0 for orientation/direction
 *  											sensitive communication
 *  @param[in]      srcIpAddr1          		Source IP address, lower address in case of address range,
 *  											set to 0 if not used
 *  @param[in]      srcIpAddr2          		upper address in case of address range, set to 0 if not used
 *  @param[in]      destIpAddr          		IP address to join
 *  @param[in]      pktFlags            		OPTION:
 *                                      		TRDP_FLAGS_DEFAULT, TRDP_FLAGS_NONE, TRDP_FLAGS_MARSHALL,
 *                                      		TRDP_FLAGS_CALLBACK
 *  @param[in]      pRecParams          		optional pointer to send parameter, NULL - default parameters are used
 *  @param[in]      timeout             		timeout (>= 10ms) in usec
 *  @param[in]      toBehavior          		timeout behavior
 *
 *  @retval         TRDP_NO_ERR         		no error
 *  @retval         TRDP_PARAM_ERR      		parameter error
 *  @retval         TRDP_MEM_ERR        		could not reserve memory (out of memory)
 *  @retval         TRDP_NOINIT_ERR     		handle invalid
 *  @retval			TRDP_SEC_NOSESSION_ERR		secure session could not be created
 */
EXT_DECL TRDP_ERR_T tau_sec_subscribe (
		TRDP_APP_SESSION_T      appHandle,
		TRDP_SUB_T              *pSubHandle,
		const void              *pUserRef,
		TRDP_PD_CALLBACK_T      pfCbFunction,
		UINT32                  serviceId,
		UINT32                  comId,
		UINT32                  etbTopoCnt,
		UINT32                  opTrnTopoCnt,
		TRDP_IP_ADDR_T          srcIpAddr1,
		TRDP_IP_ADDR_T          srcIpAddr2,
		TRDP_IP_ADDR_T          destIpAddr,
		TRDP_FLAGS_T            pktFlags,
		const TRDP_COM_PARAM_T  *pRecParams,
		UINT32                  timeout,
		TRDP_TO_BEHAVIOR_T      toBehavior)
{
	/* TODO: the second srcIP and the multicast */
	TRDP_TIME_T         now;
	TRDP_ERR_T          ret = TRDP_NO_ERR;
	TRDP_ADDRESSES_T    subHandle;
	INT32 lIndex;

	TRDPSEC_SECURE_SESSION_T *pSecHandle = NULL;

	/*    Check params    */
	if (pSubHandle == NULL)
	{
		return TRDP_PARAM_ERR;
	}

	if (!trdp_isValidSession(appHandle))
	{
		return TRDP_NOINIT_ERR;
	}

	if (timeout == 0u)
	{
		timeout = appHandle->pdDefault.timeout;
	}
	else if (timeout < TRDP_TIMER_GRANULARITY)
	{
		timeout = TRDP_TIMER_GRANULARITY;
	}

	/*    Reserve mutual access    */
	if (vos_mutexLock(appHandle->mutexRxPD) != VOS_NO_ERR)
	{
		return TRDP_NOINIT_ERR;
	}

	/*  Create an addressing item   */
	subHandle.comId         = comId;
	subHandle.srcIpAddr     = srcIpAddr1;
	/* TODO: Will be temporarily set to 0 because a publisher supports only one secure session */
	subHandle.srcIpAddr2    = 0u;
	subHandle.destIpAddr    = destIpAddr;
	subHandle.opTrnTopoCnt  = 0u;            /* Do not compare topocounts  */
	subHandle.etbTopoCnt    = 0u;
	subHandle.serviceId     = serviceId;
	TRDP_ERR_T err = TRDP_NO_ERR;

	if (vos_isMulticast(destIpAddr))
	{
		/* TODO: we do not support secure multicast in this TRDPSec version: To be fixed in later versions */
		return TRDP_PARAM_ERR;
		/* subHandle.mcGroup = destIpAddr; */
	}
	else
	{
		subHandle.mcGroup = 0u;
	}

	/*    Get the current time    */
	vos_getTime(&now);

    /*    Look for existing element    */
    if (trdp_queueFindExistingSub(appHandle->pRcvQueue, &subHandle) != NULL)
    {
        ret = TRDP_NOSUB_ERR;
    }
	else
	{
		pSecHandle = trdp_sec_addSecSession(appHandle, srcIpAddr1, 0u);
		if (pSecHandle == NULL)
		{
			return TRDP_SEC_NOSESSION_ERR;
		}

		err = trdp_sec_addHandshakeListenerBySess(appHandle, pSecHandle);
		if (err != TRDP_NO_ERR)
		{
			return err;
		}
		TRDP_SOCK_TYPE_T usage = TRDP_SOCK_PD;

		subHandle.opTrnTopoCnt  = opTrnTopoCnt; /* Set topocounts now  */
		subHandle.etbTopoCnt    = etbTopoCnt;

		if (pktFlags & (TRDP_FLAGS_TSN | TRDP_FLAGS_TSN_SDT | TRDP_FLAGS_TSN_MSDT))
		{
			usage = TRDP_SOCK_PD_TSN;
		}
		/*    Find a (new) socket    */
		ret = trdp_requestSocket(appHandle->ifacePD,
				appHandle->pdDefault.port,
				(pRecParams != NULL) ? pRecParams : &appHandle->pdDefault.sendParam,
						appHandle->realIP,
						subHandle.mcGroup,
						usage,
						appHandle->option,
						TRUE,
						-1,
						&lIndex,
						0u);

		if (ret == TRDP_NO_ERR)
		{
			PD_ELE_T *newPD;

			/*    buffer size is PD_ELEMENT plus max. payload size    */

			/*    Allocate a buffer for this kind of packets    */
			newPD = (PD_ELE_T *) vos_memAlloc(sizeof(PD_ELE_T));

			if (newPD == NULL)
			{
				ret = TRDP_MEM_ERR;
				trdp_releaseSocket(appHandle->ifacePD, lIndex, 0u, FALSE, VOS_INADDR_ANY);
			}
			else
			{
				/*  Alloc the corresponding data buffer  */
				newPD->pFrame = (PD_PACKET_T *) vos_memAlloc(TRDP_MAX_PD_PACKET_SIZE);
				if (newPD->pFrame == NULL)
				{
					vos_memFree(newPD);
					newPD   = NULL;
					ret     = TRDP_MEM_ERR;
				}
				else
				{
					/* sec Mutex must be set here */
					newPD->mustBeSecure = TRUE;
					newPD->pSecSession = pSecHandle;

					/*    Initialize some fields    */
					if (vos_isMulticast(destIpAddr))
					{
						newPD->addr.mcGroup     = destIpAddr;
						newPD->privFlags        |= TRDP_MC_JOINT;
						newPD->addr.destIpAddr  = destIpAddr;
					}
					else
					{
						newPD->addr.mcGroup     = 0u;
						newPD->addr.destIpAddr  = 0u;
					}

					newPD->addr.comId           = comId;
					newPD->addr.srcIpAddr       = srcIpAddr1;
					/* TODO: Will be temporarily set to 0 because a publisher supports only one secure session */
					newPD->addr.srcIpAddr2      = 0u;
					newPD->addr.serviceId       = serviceId;
					newPD->addr.etbTopoCnt      = etbTopoCnt;
					newPD->addr.opTrnTopoCnt    = opTrnTopoCnt;
					newPD->interval.tv_sec      = timeout / 1000000u;
					newPD->interval.tv_usec     = timeout % 1000000u;
					newPD->toBehavior           =
							(toBehavior == TRDP_TO_DEFAULT) ? appHandle->pdDefault.toBehavior : toBehavior;
					newPD->grossSize    = TRDP_MAX_PD_PACKET_SIZE;
					newPD->pUserRef     = pUserRef;
					newPD->socketIdx    = lIndex;
					newPD->privFlags    |= TRDP_INVALID_DATA;
					newPD->pktFlags     =
							(pktFlags == TRDP_FLAGS_DEFAULT) ? appHandle->pdDefault.flags : pktFlags;
					newPD->pfCbFunction =
							(pfCbFunction == NULL) ? appHandle->pdDefault.pfCbFunction : pfCbFunction;
					newPD->pCachedDS    = NULL;
					newPD->magic        = TRDP_MAGIC_SUB_HNDL_VALUE;

					if (timeout == TRDP_INFINITE_TIMEOUT)
					{
						vos_clearTime(&newPD->timeToGo);
						vos_clearTime(&newPD->interval);
					}
					else
					{
						vos_getTime(&newPD->timeToGo);
						vos_addTime(&newPD->timeToGo, &newPD->interval);
					}

					/*  append this subscription to our receive queue */
					trdp_queueAppLast(&appHandle->pRcvQueue, newPD);

					*pSubHandle = (TRDP_SUB_T) newPD;
				}
			}
		} /*lint !e438 unused newPD */
	}

	if (vos_mutexUnlock(appHandle->mutexRxPD) != VOS_NO_ERR)
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
	}

	return ret;
}

/**********************************************************************************************************************/
/** deactivate the secure session related to this subscriber
 *  the corresponding secure session is deleted and the subscriber is set as non secure
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pSubHandle          		subscription handle corresponding to the secure session to be
 *  											invalidated

 *  @retval         TRDP_NO_ERR         		no error
 *  @retval         TRDP_PARAM_ERR      		parameter error
 *  @retval         TRDP_MUTEX_ERR      		mutex error
 */
EXT_DECL TRDP_ERR_T tau_sec_invalidSubSecureSession(
		TRDP_APP_SESSION_T		appHandle,
		TRDP_SUB_T 				pSubHandle)
{
	if (!trdp_isValidSession(appHandle) || pSubHandle == NULL || pSubHandle->pSecSession == NULL)
	{
		return TRDP_PARAM_ERR;
	}

	/* Reserve mutual access to the secure sessions queue and the publisher queue */
	if (vos_mutexLock(appHandle->mutexRxPD) != VOS_NO_ERR)
	{
		return TRDP_MUTEX_ERR;
	}

	if (vos_mutexLock(appHandle->mutexSecSessQueue) != VOS_NO_ERR)
	{
		/* if the mutexSecSessQueue cannot be locked then we must unlock the mutexTxPD and return the error */
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexLock() failed\n");
		if (vos_mutexUnlock(appHandle->mutexRxPD) != VOS_NO_ERR)
		{
			vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
		}
		return TRDP_MUTEX_ERR;
	}

	trdp_sec_queueDelSecSess(&appHandle->pSecQueue, pSubHandle->pSecSession);
	pSubHandle->mustBeSecure = FALSE;
	vos_memFree(pSubHandle->pSecSession);
	pSubHandle->pSecSession = NULL;

	if ((vos_mutexUnlock(appHandle->mutexRxPD) != VOS_NO_ERR) ||
			(vos_mutexUnlock(appHandle->mutexSecSessQueue) != VOS_NO_ERR))
	{
		vos_printLogStr(VOS_LOG_INFO, "vos_mutexUnlock() failed\n");
		return TRDP_MUTEX_ERR;
	}

	return TRDP_NO_ERR;
}

