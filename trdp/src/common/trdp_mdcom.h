/******************************************************************************/
/**
 * @file            trdp_mdcom.h
 *
 * @brief           Functions for MD communication
 *
 * @details
 *
 * @note            Project: TCNOpen TRDP prototype stack
 *
 * @author          Bernd Loehr, NewTec GmbH
 *
 * @remarks All rights reserved. Reproduction, modification, use or disclosure
 *          to third parties without express authority is forbidden,
 *          Copyright Bombardier Transportation GmbH, Germany, 2012.
 *
 *
 * $Id: trdp_mdcom.h 120 2012-11-06 17:32:14Z 97025 $
 *
 */


#ifndef TRDP_MDCOM_H
#define TRDP_MDCOM_H

/*******************************************************************************
 * INCLUDES
 */

#include "trdp_private.h"

/*******************************************************************************
 * DEFINES
 */


/*******************************************************************************
 * TYPEDEFS
 */

/*******************************************************************************
 * GLOBAL FUNCTIONS
 */

TRDP_ERR_T  trdp_mdSend (
    INT32           pdSock,
    const MD_ELE_T  *pPacket);

void    trdp_mdUpdate (
    MD_ELE_T *pPacket);

TRDP_ERR_T  trdp_mdReceive (
    TRDP_SESSION_PT appHandle,
                            INT32           sock);

#endif
