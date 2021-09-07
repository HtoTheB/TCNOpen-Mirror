/**********************************************************************************************************************/
/**
 * @file            trdp_sec_types.h
 *
 * @brief           Typedefs for TRDPSEC Types
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSEC stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * @remarks This Source Code Form is subject to the terms of the NewTec GmbH terms
 */
/*
 * $Id: trdp_sec_types.h 2309 2021-09-07 11:56:44Z mohamedyoussef $
 */

#ifndef TRDPSEC_PRIVATE_H
#define TRDPSEC_PRIVATE_H

/* sudo apt-get install libssl-dev */

/*******************************************************************************
 * INCLUDES
 */

#include <stdio.h>  /*lint !e451 missing guard in std-header */

#include "vos_utils.h"
#include "trdp_types.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
/*******************************************************************************
 * DEFINES
 */

#define TRDPSEC_SECRET_LENGTH			32u
#define TRDPSEC_PRIVATE_KEY_LENGTH		32u
#define TRDPSEC_HMAC_VAL_MAX_LENGTH 	20u
#define TRDPSEC_HANDSHAKE_COMID			2000u
#define TRDPSEC_PUBLIC_KEY_LENGTH		130u

#define TRDPSEC_FLAGS_STANDARD			0u
#define TRDPSEC_FLAGS_MUST_BE_SECURE	0x01


typedef UINT8 TRDPSEC_FLAGS_T;

typedef enum
{
	TRDPSEC_INVALID_SESSION 		= 0u,
	TRDPSEC_VALID_SESSION 			= 1u,
	TRDPSEC_EXPIRED_SESSION			= 2u
}TRDPSEC_SECRET_SESSEION_STATUS_T;

typedef struct TRDPSEC_HDSHAKE_REP_CB
{
	TRDP_ERR_T 			result;
	UINT32 				expectedDatasetSize;
} TRDPSEC_HDSHAKE_REP_CB_T;

#endif
