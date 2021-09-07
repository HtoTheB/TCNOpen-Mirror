/**********************************************************************************************************************/
/**
 * @file            tau_sec.h
 *
 * @brief           API for TRDP secure communication
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSec prototype stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * $Id: tau_sec.h 2309 2021-09-07 11:56:44Z mohamedyoussef $
 */
#ifndef TAU_SEC_H
#define TAU_SEC_H

/***********************************************************************************************************************
 * INCLUDES
 */

#include "trdp_if_light.h"

#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************************************************************************
 * TYPEDEFS
 */

/** Types for trdp secure layer    */

/***********************************************************************************************************************
 * PROTOTYPES
 */

/**********************************************************************************************************************/
/*    TRDPSEC API functions                                                                                     */
/**********************************************************************************************************************/

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
 *  @param[in]      pData               		optional pointer to data packet / dataset, NULL if sending starts later
 *  											with tlp_put()
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
		UINT32					timeout);

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
		UINT32					timeout);

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
		TRDP_PUB_T 				pPubHandle);

/**********************************************************************************************************************/
/** Prepare for receiving secure PD messages.
 *  Add the corresponding secure session and a handshake listener to catch handshake requests
 *  Subscribe to a specific PD ComID and source IP.
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pSubHandle          		return a handle for this subscription
 *  @param[in]      pUserRef            		user supplied value returned within the info structure
 *  @param[in]      pfCbFunction        		Pointer to subscriber specific callback function, NULL to use
 *  											default function
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
		TRDP_TO_BEHAVIOR_T      toBehavior);

/**********************************************************************************************************************/
/** deactivate the secure session related to this subscriber
 *  the corresponding secure session is deleted and the subscriber is set as non secure
 *
 *  @param[in]      appHandle           		the handle returned by tlc_openSession
 *  @param[out]     pSubHandle          		subscription handle corresponding to the secure session to be
 *  											invalidated
 *  											invalidated

 *  @retval         TRDP_NO_ERR         		no error
 *  @retval         TRDP_PARAM_ERR      		parameter error
 *  @retval         TRDP_MUTEX_ERR      		mutex error
 */
EXT_DECL TRDP_ERR_T tau_sec_invalidSubSecureSession(
		TRDP_APP_SESSION_T		appHandle,
		TRDP_SUB_T 				pSubHandle);



#ifdef __cplusplus
}
#endif

#endif  /* TAU_SEC_H    */
