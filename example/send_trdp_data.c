/******************************************************************************/
/**
 * @file            send_trdp_data.c
 *
 * @brief           Demo send application to simulate an attacker device
 * 					stealing the identity of a secure one
 *
 * @details
 *
 * @note            Project: TCNOpen TRDPSec prototype stack
 *
 * @author          Mohamed Youssef, NewTec GmbH
 *
 * $Id: send_trdp_data.c 2309 2021-09-07 11:56:44Z mohamedyoussef $
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
static void usage (const char *appName)
{
    printf("Usage of %s\n", appName);
    printf("This tool sends PD Secure messages with static data.\n"
           "Arguments are:\n"
           "-o <own IP address> (default INADDR_ANY)\n"
           "-d <target IP address>\n"
           "-c <comId> (default 0)\n"
           "-t <cycle time> (default 1000000 [us])\n"
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

/**********************************************************************************************/
int main(int argc, char *argv[])
{
	TRDP_APP_SESSION_T appHandle = NULL;
    unsigned int    ip[4];
	TRDP_IP_ADDR_T ownIP = 0x0a00010c;
	TRDP_IP_ADDR_T destIP = 0x0a00010d;
    UINT32	comId = COMID_1;
    UINT32 interval = CYCLE_TIME;
    int ch;
    DATASET_T *pData;
	TRDP_ERR_T err = TRDP_NO_ERR;
	TRDP_PUB_T pubHandle_1;
	CHAR8 send_str[] = " seconds since communication start";

	/* Data to be sent */
    pData = (DATASET_T*) vos_memAlloc(sizeof(DATASET_T));
	memcpy(pData->str, send_str, sizeof(send_str));

	UINT32 datasetSize = sizeof(DATASET_T);

	    if (argc <= 1)
	    {
	        usage(argv[0]);
	        return 1;
	    }

	    while ((ch = getopt(argc, argv, "o:c:t:d:h?v:")) != -1)
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
	           case 'd':
	           {    /*  read ip    */
	               if (sscanf(optarg, "%u.%u.%u.%u",
	                          &ip[3], &ip[2], &ip[1], &ip[0]) < 4)
	               {
	                   usage(argv[0]);
	                   exit(1);
	               }
	               destIP = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
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

	    if (destIP == 0)
	    {
	        fprintf(stderr, "No destination address given!\n");
	        usage(argv[0]);
	        return 1;
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

	/*    Open a TRDP session  */
	err = trdpsec_openSession(&appHandle, ownIP, 0, NULL, NULL, NULL);
	if (err != TRDP_NO_ERR)
	{
		printf("tlc_openSession");
		return err;
	}

	err = tlp_publish (
			appHandle,      			/*    our application identifier                		*/
			&pubHandle_1, 				/*    our publication identifier                		*/
			NULL, NULL,
			0u,
			COMID_1,             		/*    ComID to send                             		*/
			0u,                       	/*    etbTopoCnt = 0 for local consist only     		*/
			0u,                      	/*    opTopoCnt = 0 for non-directinal data     		*/
			ownIP,     					/*    default source IP                         		*/
			destIP, 					/*    where to send to                          		*/
			interval,     				/*    Cycle time in us                          		*/
			0u,                       	/*    not redundant                             		*/
			TRDP_FLAGS_DEFAULT,         /*    Use callback for errors                   		*/
			NULL,                     	/*    default qos and ttl                       		*/
			NULL,                     	/*    initial data                              		*/
			0u);                       	/*    data size                                 		*/

	if (err != TRDP_NO_ERR)
	{
		printf("nt_tip_publish() on comId %d", COMID_1);
		return err;
	}

	while(TRUE)
	{
		err = tlp_put(appHandle, pubHandle_1, (UINT8*) pData, datasetSize);
		if (err != TRDP_NO_ERR)
		{
			printf("nt_tlp_put() on comId %d", COMID_1);
			return err;
		}
		pData->counter += 2;

		vos_threadDelay(2000000); /* wait for 2000000 us = 2s */
	}

	/* clean up and close */
	(void)tlp_unpublish(appHandle, pubHandle_1);
	(void)tlc_closeSession(appHandle);

	return err;
}
