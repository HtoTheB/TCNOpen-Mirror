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

#ifdef TRDPSEC
#include "trdp_sec_utils.h"
#endif

#define COMID_1 10001u
#define COMID_2 10002u
#define CYCLE_TIME 1000000u

VOS_THREAD_T testComThread;
VOS_THREAD_T testReceiverThread;
VOS_THREAD_T testSenderThread;
VOS_THREAD_T testTransceiverThread;

BOOL8 testReceiverThreadRunning;
BOOL8 testTransceiverThreadRunning;
BOOL8 testComThreadRunning;

#ifdef HIGH_PERF_INDEXED /** TODO: set to ifdef */

static void *receiverThreadPD(void *pArg);

static void *senderThreadPD(void *pArg);

static void *transceiverThreadMD(void *pArg);

#else
static void *comThread(void *pArg);
#endif

TRDP_ERR_T trdpsec_openSession (TRDP_APP_SESSION_T *         pAppHandle,
		TRDP_IP_ADDR_T               ownIpAddr,
		TRDP_IP_ADDR_T               leaderIpAddr,
		const TRDP_PD_CONFIG_T *     pPdDefault,
		const TRDP_MD_CONFIG_T *     pMdDefault,
		const TRDP_PROCESS_CONFIG_T *pProcessConfig);

TRDP_ERR_T trdpsec_closeSession (TRDP_APP_SESSION_T appHandle);

void dbgOut (
		void        *pRefCon,
		TRDP_LOG_T  category,
		const CHAR8 *pTime,
		const CHAR8 *pFile,
		UINT16      LineNumber,
		const CHAR8 *pMsgStr);

