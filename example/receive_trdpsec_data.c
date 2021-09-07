/******************************************************************************/
/**
 * @file            receive_trdpsec_data.c
 *
 * @brief           Demo receive application for the TRDPSec extension
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSec prototype stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * $Id: receive_trdpsec_data.c 2309 2021-09-07 11:56:44Z mohamedyoussef $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (POSIX)
#include <unistd.h>
#include <sys/select.h>
#elif (defined (WIN32) || defined (WIN64))
#include "getopt.h"
#endif

#include "trdp_if_light.h"
#include "vos_thread.h"
#include "vos_utils.h"

#include "trdpsec_test_if.h"

#ifdef TRDPSEC
#include "tau_sec.h"
#endif

/***********************************************************************************************************************
 * DEFINITIONS
 */

#define COMID_1 		10001u
#define COMID_2 		10002u
#define CYCLE_TIME 		1000000u
#define APP_VERSION     "1.0"

/***********************************************************************************************************************
 * LOCAL FUNCTIONS
 */

/* Print a sensible usage message */
void usage (const char *appName)
{
	printf("Usage of %s\n", appName);
	printf("This tool receives PD Secure static messages from an ED.\n"
			"Arguments are:\n"
			"-o <own IP address> (default: default interface)\n"
			"-s <src IP address> (default: 0)\n"
			"-c <comId> (default 0)\n"
			"-v print version and quit\n"
	);
}

/***********************************************************************************************************************
 * TYPEDEFS
 */

typedef struct
{
	UINT32 counter;
	UINT8 str[100u];
}DATASET_T;

int main(int argc, char *argv[])
{
	TRDP_APP_SESSION_T appHandle = NULL;
	unsigned int    ip[4];
	TRDP_IP_ADDR_T srcIP = 0u;
	TRDP_IP_ADDR_T ownIP = 0x0a00010d;
	UINT32	comId = COMID_1;
	UINT32 interval = CYCLE_TIME;
	int ch;
	UINT8 dataset[104u];
	DATASET_T *pDataRcv;
	UINT32 datasetSize = sizeof(DATASET_T);
	TRDP_ERR_T err = TRDP_NO_ERR;
	TRDP_PD_INFO_T info;

	TRDP_SUB_T subHandle_1;

	while ((ch = getopt(argc, argv, "o:s:c:t:?v:")) != -1)
	{
		switch (ch)
		{
		case 'o':
		{    /*  read ip    */
			if (sscanf(optarg, "%u.%u.%u.%u",
					&ip[3], &ip[2], &ip[1], &ip[0]) < 4)
			{
				usage(argv[0]);
				exit(1);
			}
			ownIP = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
			break;
		}
		case 's':
		{    /*  read ip    */
			if (sscanf(optarg, "%u.%u.%u.%u",
					&ip[3], &ip[2], &ip[1], &ip[0]) < 4)
			{
				usage(argv[0]);
				exit(1);
			}
			srcIP = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
			break;
		}
		case 'c':
		{    /*  read comId    */
			if (sscanf(optarg, "%u",
					&comId) < 1)
			{
				usage(argv[0]);
				exit(1);
			}
			break;
		}
		case 't':
		{    /*  read cycle time    */
			if (sscanf(optarg, "%u",
					&interval) < 1 )
			{
				usage(argv[0]);
				exit(1);
			}
			break;
		}
		case 'v':    /*  version */
			printf("%s: Version %s\t(%s - %s)\n",
					argv[0], APP_VERSION, __DATE__, __TIME__);
			exit(0);
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/*    Init the library  */
	err = tlc_init(dbgOut, /* no logging    */
			NULL,
			NULL);
	if (err != TRDP_NO_ERR)
	{
		printf("nt_tic_init()");
		return err;
	}

	/*    Open a test case session  */
	err = trdpsec_openSession(&appHandle, ownIP, 0, NULL, NULL, NULL);
	if (err != TRDP_NO_ERR)
	{
		printf("tlc_openSession");
		return err;
	}

	tau_sec_subscribe (appHandle,
			&subHandle_1,
			NULL, NULL,
			0,
			COMID_1,
			0,0,
			srcIP,
			0,
			ownIP,
			TRDP_FLAGS_DEFAULT,
			NULL,
			interval,
			TRDP_TO_SET_TO_ZERO);
	while(TRUE)
	{
		err = tlp_get(appHandle, subHandle_1, &info, dataset, &datasetSize);
		if (dataset != NULL && datasetSize != 0 && err == TRDP_NO_ERR)
		{
			pDataRcv = (DATASET_T *) dataset;
			printf("%i %s\n", pDataRcv->counter, pDataRcv->str);
		}

		vos_threadDelay(interval - (interval / 10)); /* we poll with a higher frequency to receive */
	}

	/* clean up and close */
	(void)tlp_unsubscribe(appHandle, subHandle_1);
	(void)tlc_closeSession(appHandle);

	return err;
}
