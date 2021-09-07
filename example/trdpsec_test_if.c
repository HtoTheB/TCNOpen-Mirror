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
#include "trdp_sec_utils.h"
#endif

#ifdef HIGH_PERF_INDEXED /** TODO: set to ifdef */

/*********************************************************************************************************************/
/** Call tlp_processReceive asynchronously
 */
static void *receiverThreadPD(void *pArg)
{
	TRDP_ERR_T  result;
	TRDP_TIME_T interval = {0, 0};
	TRDP_TIME_T maxInterval = {0, 20000};
	TRDP_TIME_T minInterval = {0, 5000};
	TRDP_FDS_T  fileDesc;
	INT32       noDesc = 0;

	TRDP_APP_SESSION_T appHandle = (TRDP_APP_SESSION_T)pArg;
	/*
     Enter the main processing loop.
	 */

	while (testReceiverThreadRunning) /* this is a cancelation point! */
	{
		FD_ZERO(&fileDesc);
		result = tlp_getInterval(appHandle, &interval, &fileDesc, &noDesc);
		if (result != TRDP_NO_ERR)
		{
			vos_printLog(VOS_LOG_ERROR, "tlp_getInterval failed: %s\n", vos_getErrorString((VOS_ERR_T)result));
		}
		if (vos_cmpTime(&maxInterval, &interval) < 0)
		{

		}
		else if (vos_cmpTime(&minInterval, &interval) > 0)
		{
			interval = minInterval;
		}
		noDesc = vos_select(noDesc + 1, &fileDesc, NULL, NULL, &interval);
		result = tlp_processReceive(appHandle, &fileDesc, &noDesc);
		if ((result != TRDP_NO_ERR) && (result != TRDP_BLOCK_ERR))
		{
			vos_printLog(VOS_LOG_ERROR, "tlp_processReceive failed: %s\n", vos_getErrorString((VOS_ERR_T)result));
		}
	}

	return NULL;
}

/*********************************************************************************************************************/
/** Call tlp_processSend synchronously
 */
static void *senderThreadPD(void *pArg)
{
	TRDP_APP_SESSION_T appHandle = (TRDP_APP_SESSION_T)pArg;
	TRDP_ERR_T         result    = tlp_processSend(appHandle);
	if ((result != TRDP_NO_ERR) && (result != TRDP_BLOCK_ERR))
	{
		vos_printLog(VOS_LOG_ERROR, "tlp_processSend failed: %s\n", vos_getErrorString((VOS_ERR_T)result));
	}
	return NULL;
}

/*********************************************************************************************************************/
/** Call tlm_process
 */
static void *transceiverThreadMD(void *pArg)
{
	TRDP_ERR_T  result;
	TRDP_TIME_T interval = {0, 0};
	TRDP_FDS_T  fileDesc;
	INT32       noDesc = 0;

	TRDP_APP_SESSION_T appHandle = (TRDP_APP_SESSION_T)pArg;
	/*
     Enter the main processing loop.
	 */
	while (testTransceiverThreadRunning) /* this is a cancelation point! */
	{
		FD_ZERO(&fileDesc);
		result = tlm_getInterval(appHandle, &interval, &fileDesc, &noDesc);
		if (result != TRDP_NO_ERR)
		{
			vos_printLog(VOS_LOG_ERROR, "tlm_getInterval failed: %s\n", vos_getErrorString((VOS_ERR_T)result));
		}
		noDesc = vos_select(noDesc + 1, &fileDesc, NULL, NULL, &interval);
		result = tlm_process(appHandle, &fileDesc, &noDesc);
		if ((result != TRDP_NO_ERR) && (result != TRDP_BLOCK_ERR))
		{
			vos_printLog(VOS_LOG_ERROR, "tlm_process failed: %s\n", vos_getErrorString((VOS_ERR_T)result));
		}
	}
	return NULL;
}
#else

/*********************************************************************************************************************/
/** Communication Thread
 */
static void *comThread(void *pArg)
{
	TRDP_APP_SESSION_T apphandle = (TRDP_APP_SESSION_T)pArg;

	TRDP_ERR_T  result;
	TRDP_TIME_T interval    = {0, 0};
	TRDP_TIME_T maxInterval = {0, 20000};
	TRDP_TIME_T minInterval = {0, 5000};
	TRDP_FDS_T  fileDesc;
	INT32       noDesc = 0;

	while (testComThreadRunning) /* this is a cancelation point! */
	{
		FD_ZERO(&fileDesc);
		result = tlc_getInterval(apphandle, &interval, &fileDesc, &noDesc);
		if (result != TRDP_NO_ERR)
		{
			printf("tlc_getInterval failed: %d\n", result);
		}
		if (vos_cmpTime(&maxInterval, &interval) < 0)
		{

		}
		else if (vos_cmpTime(&minInterval, &interval) > 0)
		{
			interval = minInterval;
		}
		noDesc = vos_select(noDesc + 1, &fileDesc, NULL, NULL, &interval);
		result = tlc_process(apphandle, &fileDesc, &noDesc);
		if ((result != TRDP_NO_ERR) && (result != TRDP_BLOCK_ERR))
		{
			printf("tlc_process failed: %d\n", result);
		}
	}
	return NULL;
}
#endif

/**********************************************************************************************/
TRDP_ERR_T trdpsec_openSession(
		TRDP_APP_SESSION_T *         pAppHandle,
		TRDP_IP_ADDR_T               ownIpAddr,
		TRDP_IP_ADDR_T               leaderIpAddr,
		const TRDP_PD_CONFIG_T *     pPdDefault,
		const TRDP_MD_CONFIG_T *     pMdDefault,
		const TRDP_PROCESS_CONFIG_T *pProcessConfig)
{
	TRDP_ERR_T            err           = TRDP_NO_ERR;
	TRDP_PROCESS_CONFIG_T processConfig = {"DuT", "testPC", 5000u, 0u, TRDP_OPTION_DEFAULT_CONFIG};

	err = tlc_openSession(pAppHandle,
			ownIpAddr, leaderIpAddr,                                        /* use default IP address           */
			NULL,                                                           /* no Marshalling                   */
			(TRDP_PD_CONFIG_T *)pPdDefault, (TRDP_MD_CONFIG_T *)pMdDefault, /* system defaults for PD and MD    */
			(TRDP_PROCESS_CONFIG_T *)&processConfig);

	if (err != TRDP_NO_ERR)
	{
		return err;
	}
#ifdef HIGH_PERF_INDEXED
	err = tlc_presetIndexSession(*pAppHandle, NULL);
	if (err != TRDP_NO_ERR)
	{
		return err;
	}
	testReceiverThreadRunning    = TRUE;
	testTransceiverThreadRunning = TRUE;
	err                          = vos_threadCreate(&testReceiverThread,
			"Receiver Task",
			VOS_THREAD_POLICY_OTHER,
			(VOS_THREAD_PRIORITY_T)VOS_THREAD_PRIORITY_DEFAULT,
			0u,
			0u,
			(VOS_THREAD_FUNC_T)receiverThreadPD,
			*pAppHandle);
	if (err != TRDP_NO_ERR)
	{
		return err;
	}

	err = vos_threadCreate(&testSenderThread,
			"Sender Task",
			VOS_THREAD_POLICY_OTHER,
			(VOS_THREAD_PRIORITY_T)VOS_THREAD_PRIORITY_HIGHEST,
			processConfig.cycleTime,
			0u,
			(VOS_THREAD_FUNC_T)senderThreadPD,
			*pAppHandle);
	if (err != TRDP_NO_ERR)
	{
		return err;
	}

	err = vos_threadCreate(&testTransceiverThread,
			"Transceiver Task",
			VOS_THREAD_POLICY_OTHER,
			(VOS_THREAD_PRIORITY_T)VOS_THREAD_PRIORITY_DEFAULT,
			0u,
			0u,
			(VOS_THREAD_FUNC_T)transceiverThreadMD,
			*pAppHandle);

#else
	testComThreadRunning = TRUE;
	err                  = vos_threadCreate(&testComThread, "Receiver Thread",
			VOS_THREAD_POLICY_OTHER, (VOS_THREAD_PRIORITY_T)VOS_THREAD_PRIORITY_DEFAULT,
			0u, 0u,
			(VOS_THREAD_FUNC_T)comThread, *pAppHandle);

#endif

	/* Better wait until the session is ready: Allow 200 ms for thread creation */
	vos_threadDelay(200000u); /* 200 ms */

	return err;
}

/**********************************************************************************************/
TRDP_ERR_T trdpsec_closeSession(
		TRDP_APP_SESSION_T appHandle)
{
	TRDP_ERR_T err = TRDP_NO_ERR;

	/* Terminate running threads */
#ifdef HIGH_PERF_INDEXED

	testReceiverThreadRunning = FALSE;
	(void)vos_threadDelay(20000u);
	while (VOS_NO_ERR == vos_threadIsActive(testReceiverThread))
	{
		if (VOS_NO_ERR == vos_threadTerminate(testReceiverThread))
		{
			break;
		}
		(void)vos_threadDelay(20000u);
	}

	do
	{
		(void)vos_threadDelay(20000u);
		if (VOS_NO_ERR == vos_threadTerminate(testSenderThread))
		{
			break;
		}
	} while (VOS_NO_ERR == vos_threadIsActive(testSenderThread));

	testTransceiverThreadRunning = FALSE;
	(void)vos_threadDelay(20000u);
	while (VOS_NO_ERR == vos_threadIsActive(testTransceiverThread))
	{
		if (VOS_NO_ERR == vos_threadTerminate(testTransceiverThread))
		{
			break;
		}
		(void)vos_threadDelay(20000u);
	}

#else

	testComThreadRunning = FALSE;
	(void)vos_threadDelay(20000u);
	while (VOS_NO_ERR == vos_threadIsActive(testComThread))
	{

		if (VOS_NO_ERR == vos_threadTerminate(testComThread))
		{
			break;
		}
		(void)vos_threadDelay(20000u);
	}
#endif

	/* close the application session */
	err |= tlc_closeSession(appHandle);
	err |= tlc_terminate();
	return err;
}

/**********************************************************************************************/
void dbgOut (
		void        *pRefCon,
		TRDP_LOG_T  category,
		const CHAR8 *pTime,
		const CHAR8 *pFile,
		UINT16      LineNumber,
		const CHAR8 *pMsgStr)
{
	(void) pRefCon;

	const char *catStr[] = {"**Error:", "Warning:", "   Info:", "  Debug:", "   User:"};
	CHAR8       *pF = strrchr(pFile, VOS_DIR_SEP);
	printf("%s %s %s:%d %s",
			strrchr(pTime, '-') + 1,
			catStr[category],
			(pF == NULL)? "" : pF + 1,
					LineNumber,
					pMsgStr);
}
