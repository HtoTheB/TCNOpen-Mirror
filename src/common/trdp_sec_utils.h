/******************************************************************************/
/**
 * @file            trdp_sec_utils.h
 *
 * @brief           Common utilities for TRDP secure communication
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSec prototype stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * $Id: trdp_sec_utils.h 2309 2021-09-07 11:56:44Z mohamedyoussef $
 */


#ifndef TRDPSEC_UTILS_H
#define TRDPSEC_UTILS_H

/* sudo apt-get install libssl-dev */


/*******************************************************************************
 * INCLUDES
 */

#include <stdio.h>  /*lint !e451 missing guard in std-header */

#include "trdp_private.h"
#include "vos_utils.h"
#include "trdp_types.h"
#include "trdp_sec_types.h"
/*******************************************************************************
 * DEFINES
 */


/*******************************************************************************
 * GLOBAL FUNCTIONS
 */

EXT_DECL TRDP_ERR_T trdp_sec_queueFindSecSession(
		TRDP_APP_SESSION_T 			appHandle,
		TRDP_IP_ADDR_T				addr,
		TRDPSEC_SECURE_SESSION_T *	*ppElem);

EXT_DECL TRDP_ERR_T	trdp_sec_addSecSessionByAddr(
		TRDP_APP_SESSION_T			appHandle,
		TRDP_IP_ADDR_T				addr,
		UINT32						secFlag);

EXT_DECL TRDPSEC_SECURE_SESSION_T*	trdp_sec_addSecSession (
		TRDP_APP_SESSION_T			appHandle,
		TRDP_IP_ADDR_T				addr,
		UINT32						secFlag);

EXT_DECL void trdp_sec_queueInsSecSession(
		TRDPSEC_SECURE_SESSION_T    * *ppHead,
		TRDPSEC_SECURE_SESSION_T    *pNew);

void    trdp_sec_queueDelSecSess (
		TRDPSEC_SECURE_SESSION_T    * *ppHead,
		TRDPSEC_SECURE_SESSION_T    *pDelete);

EXT_DECL UINT32	trdp_sec_hmac(
		const void					*pKey,
		INT32 						keySize,
		const UINT8					*pPacket,
		UINT16 						packetSize);

EXT_DECL void trdp_sec_requesterCallback(
		void *                 pRefCon,
		TRDP_APP_SESSION_T     appHandle,
		const TRDP_MD_INFO_T   *pMsg,
		UINT8 *                pData,
		UINT32                 dataSize);

EXT_DECL void trdp_sec_replierCallback(
		void *                 pRefCon,
		TRDP_APP_SESSION_T     appHandle,
		const TRDP_MD_INFO_T   *pMsg,
		UINT8 *                pData,
		UINT32                 dataSize);

EXT_DECL TRDP_ERR_T trdp_sec_handshakeByAddr(
		TRDP_APP_SESSION_T 	appHandle,
		TRDP_IP_ADDR_T 		srcIpAddr,
		TRDP_IP_ADDR_T 		destIpAddr,
		UINT32 				timeout);

EXT_DECL TRDP_ERR_T trdp_sec_initiateHandshake(
		TRDP_APP_SESSION_T 			appHandle,
		TRDPSEC_SECURE_SESSION_T 	*pSecHandle,
		UINT32 timeout);

EXT_DECL TRDP_ERR_T trdp_sec_addHandshakeListener(
		TRDP_APP_SESSION_T		appHandle,
		TRDP_IP_ADDR_T          srcIpAddr);

EXT_DECL TRDP_ERR_T trdp_sec_addHandshakeListenerBySess(
		TRDP_APP_SESSION_T			appHandle,
		TRDPSEC_SECURE_SESSION_T 	*pSecHandle);

EXT_DECL TRDP_ERR_T trdp_sec_pdCheck (
		PD_HEADER_T *pPacket,
		UINT32      packetSize,
		PD_ELE_T	*pPDElem,
		int         *pIsTSN);

#endif /*TRDPSEC_UTILS_H*/
