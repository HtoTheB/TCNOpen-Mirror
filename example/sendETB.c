/**********************************************************************************************************************/
/**
 * @file            sendETB.c
 *
 * @brief           Demo application for TRDP
 *
 * @note            Project: TCNOpen TRDP prototype stack
 *
 * @author          Bernd Loehr and Florian Weispfenning, NewTec GmbH and Matthias Moßner Siemens Mobility GmbH
 *
 * @remarks This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 *          If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * $Id: sendETB.c 1441 2015-09-04 13:46:12Z z00306dr $
 *
 */

/***********************************************************************************************************************
 * INCLUDES
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (POSIX)
#include <unistd.h>
#include <sys/select.h>
#elif defined (WIN32)
#include "getopt.h"
#endif

#include "trdp_if_light.h"
#include "vos_thread.h"
#include "vos_utils.h"
#include "tau_tti.h"
#include "iec61375-2-3.h"


/***********************************************************************************************************************
 * DEFINITIONS
 */
#define DATA_MAX        1000

#define PD_COMID_CYCLE  1000000             /* in us (1000000 = 1 sec) */

#define CONFIG_FILE     "sendETB.cfg"

/* We use dynamic memory    */
#define RESERVED_MEMORY  160000

/**********************************************************************************************************************/
/** callback routine for TRDP logging/error output
 *
 *  @param[in]      pRefCon            user supplied context pointer
 *  @param[in]        category        Log category (Error, Warning, Info etc.)
 *  @param[in]        pTime            pointer to NULL-terminated string of time stamp
 *  @param[in]        pFile            pointer to NULL-terminated string of source module
 *  @param[in]        LineNumber        line
 *  @param[in]        pMsgStr         pointer to NULL-terminated string
 *  @retval         none
 */
void dbgOut (
    void        *pRefCon,
    TRDP_LOG_T  category,
    const CHAR8 *pTime,
    const CHAR8 *pFile,
    UINT16      LineNumber,
    const CHAR8 *pMsgStr)
{
    const char *catStr[] = {"**Error:", "Warning:", "   Info:", "  Debug:"};
    printf("%s %s %s:%d %s",
           strrchr(pTime, '-') + 1,
           catStr[category],
           strrchr(pFile, '/') + 1,
           LineNumber,
           pMsgStr);
}

/* Print a sensible usage message */
void usage (const char *appName)
{
    printf("Usage of %s\n", appName);
    printf("This tool sends PD messages to an ED.\n"
           "Arguments are:\n"
           "-c <opTrnTopoCount> (default 0)\n"
           "-e <etbTopoCount> (default 0)\n"
           "-n <ownOpCstNo> (default 0)\n"
           "-m <ownTrnCstNo> (default 0)\n"
           "-o <own IP address> (default INADDR_ANY)\n"
           "-t <target IP address>\n"
           "-s <cycle time> (default 1000000 [us])\n"
           );
}

/**********************************************************************************************************************/
/** setup tti data
 *
 *  @retval         0        no error
 *  @retval         1        some error
 */
 int setup_tti_data(TRDP_APP_SESSION_T appHandle, UINT32 etbTopoCnt, UINT32 opTrnTopoCnt, UINT8 ownOpCstNo, UINT32 ownTrnCstNo, TRDP_OP_TRAIN_DIR_STATUS_INFO_T *pTelegram )
{
    if (pTelegram == NULL)
    {
        fprintf(stderr, "pTelegram is empty on setting up data!\n");
        return 1;
    }
    pTelegram->state.version.ver = 1; 
    pTelegram->state.version.rel = 1;  /**< TrainDirectoryState data structure version  
                                                 parameter 'mainVersion' shall be set to 1. */
    pTelegram->state.reserved01 = 0;     /**< reserved for future use (= 0) */
    pTelegram->state.reserved02 = 0;     /**< reserved for future use (= 0) */
    pTelegram->state.etbId = 0;          /**< identification of the ETB the TTDB is computed for
                                                 0: ETB0 (operational network)
                                                 1: ETB1 (multimedia network)
                                                 2: ETB2 (other network)
                                                 3: ETB3 (other network) */
    pTelegram->state.trnDirState = 2;    /**< TTDB status: '01'B == unconfirmed, '10'B == confirmed */
    pTelegram->state.opTrnDirState = 2;  /**< Operational train directory status:
                                                 '01'B == invalid, '10'B == valid, '100'B == shared */
    pTelegram->state.reserved03 = 0;     /**< reserved for future use (= 0) */
    snprintf(pTelegram->state.trnId, TRDP_MAX_LABEL_LEN, "ICX");          /**< train identifier, application defined
                                                                        (e.g. 'ICE75', 'IC346'), informal */
    snprintf(pTelegram->state.trnOperator, TRDP_MAX_LABEL_LEN, "Siemens");    /**< train operator, e.g. 'trenitalia.it', informal */
    pTelegram->state.opTrnTopoCnt = vos_htonl(opTrnTopoCnt);   /**< operational train topology counter
                                                 set to 0 if opTrnDirState == invalid */
                
    /* calculate the crc:   */
    pTelegram->state.crc = vos_htonl(vos_sc32(0xFFFFFFFF, (const UINT8 *) &pTelegram->state, sizeof(TRDP_OP_TRAIN_DIR_STATE_T) - 4));    /**< sc-32 computed over record (seed value: 'FFFFFFFF'H) */            
    pTelegram->etbTopoCnt = vos_htonl(etbTopoCnt);
    pTelegram->ownOpCstNo = ownOpCstNo;
    pTelegram->ownTrnCstNo = ownTrnCstNo;
    pTelegram->reserved02 = 0;
    pTelegram->safetyTrail.reserved01 = 0;     /**< reserved (=0) */
    pTelegram->safetyTrail.reserved02 = 0;     /**< reserved (=0) */
    pTelegram->safetyTrail.userDataVersion.ver = 1;
    pTelegram->safetyTrail.userDataVersion.rel = 1; /**< version of the vital ETBCTRL telegram
                                             mainVersion = 1, subVersion = 0 */
    pTelegram->safetyTrail.safeSeqCount = 0;   /**< safe sequence counter, as defined in B.9 */
    pTelegram->safetyTrail.safetyCode = 0;     /**< checksum, as defined in B.9 TODO*/

    return 0;
}

/**********************************************************************************************************************/
/** main entry
 *
 *  @retval         0        no error
 *  @retval         1        some error
 */
int main (int argc, char *argv[])
{
    int                     ip[4];
    TRDP_APP_SESSION_T      appHandle; /*    Our identifier to the library instance    */
    TRDP_PUB_T              pubHandle; /*    Our identifier to the publication         */
    UINT32                  comId       = TRDP_TTDB_OP_TRAIN_DIR_STATUS_INFO_COMID;
    UINT32                  cycleTime   = PD_COMID_CYCLE;
    TRDP_ERR_T              err;
    TRDP_PD_CONFIG_T        pdConfiguration = {NULL, NULL, {0, 64}, TRDP_FLAGS_NONE, 1000, TRDP_TO_SET_TO_ZERO, 0};
    TRDP_MEM_CONFIG_T       dynamicConfig   = {NULL, RESERVED_MEMORY, {0}};
    TRDP_PROCESS_CONFIG_T   processConfig   = {"Me", "", 0, 0, TRDP_OPTION_BLOCK};
    UINT32                  ownIP   = 0;
    int                     rv      = 0;
    UINT32                  destIP  = 0;
    UINT32                  etbTopoCnt = 1, opTrnTopoCnt = 1, etbTopoCnt_old = 0, opTrnTopoCnt_old = 0;
    UINT32                  ownOpCstNo_32 = 1, ownTrnCstNo_32 = 1;
    UINT8                   ownOpCstNo = 1, ownTrnCstNo = 1, ownOpCstNo_old = 0, ownTrnCstNo_old = 0;
    UINT8                   data[DATA_MAX];
    TRDP_OP_TRAIN_DIR_STATUS_INFO_T *pTelegram = (TRDP_OP_TRAIN_DIR_STATUS_INFO_T *) data;
    int                     ch;
    FILE                    *cfg_file;

    if (argc <= 1)
    {
        usage(argv[0]);
        return 1;
    }

    while ((ch = getopt(argc, argv, "t:o:e:c:s:e:n:m:h?:")) != -1)
    {
        switch (ch)
        {
            case 'c':
            {   /*  read opTrnTopoCount    */
                if (sscanf(optarg, "%u",
                           &opTrnTopoCnt) < 1)
                {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            }
            case 'e':
            {   /*  read etbTopoCount    */
                if (sscanf(optarg, "%u",
                           &etbTopoCnt) < 1)
                {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            }
            case 'n':
            {   /*  read  ownOpCstNo   */
                if (sscanf(optarg, "%u",
                           &ownOpCstNo) < 1)
                {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            }
            case 'm':
            {   /*  read ownTrnCstNo  */
                if (sscanf(optarg, "%u",
                           &ownTrnCstNo) < 1)
                {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            }
            case 'o':
            {   /*  read ip    */
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
            {   /*  read cycle time    */
                if (sscanf(optarg, "%u",
                           &cycleTime) < 1)
                {
                    usage(argv[0]);
                    exit(1);
                }
                break;
            }
            case 't':
            {   /*  read ip    */
                if (sscanf(optarg, "%u.%u.%u.%u",
                           &ip[3], &ip[2], &ip[1], &ip[0]) < 4)
                {
                    usage(argv[0]);
                    exit(1);
                }
                destIP = (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0];
                break;
            }

            case 'h':
            case '?':
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (destIP == 0)
    {
        destIP = vos_dottedIP(TTDB_STATUS_DEST_IP);
    }
    
    cfg_file = fopen(CONFIG_FILE,"r");
    if (cfg_file)
    {
        fscanf(cfg_file,"E:%d\nO:%d\nC:%d\nT:%d", &etbTopoCnt, &opTrnTopoCnt, &ownOpCstNo_32, &ownTrnCstNo_32);
        ownOpCstNo = (UINT8) ownOpCstNo_32;
        ownTrnCstNo = (UINT8) ownTrnCstNo_32;
        printf("\nCfgFile: EtbTopoCount=%u OpTrainTopocount=%u ownOpCstNo=%u ownTrnCstNo=%u\n",
            etbTopoCnt, opTrnTopoCnt, ownOpCstNo, ownTrnCstNo);
        etbTopoCnt_old = etbTopoCnt;
        opTrnTopoCnt_old = opTrnTopoCnt;
        ownOpCstNo_old = ownOpCstNo;
        ownTrnCstNo_old = ownTrnCstNo;
        fclose(cfg_file);
    } else {
        printf("Argument: EtbTopoCount=%u OpTrainTopocount=%u ownOpCstNo=%u ownTrnCstNo=%u\n", etbTopoCnt, opTrnTopoCnt);
    }

    /*    Init the library  */
    if (tlc_init(&dbgOut,                              /* no logging    */
                 NULL,
                 &dynamicConfig) != TRDP_NO_ERR)    /* Use application supplied memory    */
    {
        printf("Initialization error\n");
        return 1;
    }

    /*    Open a session  */
    if (tlc_openSession(&appHandle,
                        ownIP, 0,               /* use default IP address           */
                        NULL,                   /* no Marshalling                   */
                        &pdConfiguration, NULL, /* system defaults for PD and MD    */
                        &processConfig) != TRDP_NO_ERR)
    {
        printf("Initialization error\n");
        return 1;
    }

    /*    Copy the packet into the internal send queue, prepare for sending.    */
    /*    If we change the data, just re-publish it    */
    err = tlp_publish(  appHandle,                  /*    our application identifier    */
                        &pubHandle,                 /*    our pulication identifier     */
                        comId,                      /*    ComID to send                 */
                        0,                          /*    local consist only            */
                        0,
                        ownIP,                      /*    default source IP             */
                        destIP,                     /*    where to send to              */
                        cycleTime,                  /*    Cycle time in us              */
                        0,                          /*    not redundant                 */
                        TRDP_FLAGS_NONE,            /*    Use callback for errors       */
                        NULL,                       /*    default qos and ttl           */
                        NULL,      /*    initial data                  */
                        0            /*    data size                     */
                        );


    if (err != TRDP_NO_ERR)
    {
        printf("prep pd error\n");
        tlc_terminate();
        return 1;
    }

    /*
       Enter the main processing loop.
     */
    while (1)
    {
        TRDP_FDS_T  rfds;
        INT32       noDesc;
        TRDP_TIME_T tv;
        const TRDP_TIME_T max_tv = {0, 5000000};
        const TRDP_TIME_T min_tv = {0, 500000};

        /*
           Prepare the file descriptor set for the select call.
           Additional descriptors can be added here.
         */
        FD_ZERO(&rfds);
        /* FD_SET(pd_fd, &rfds); */

        /*
           Compute the min. timeout value for select.
           This way we can guarantee that PDs are sent in time
           with minimum CPU load and minimum jitter.
         */
        tlc_getInterval(appHandle, &tv, &rfds, &noDesc);

        /*
           The wait time for select must consider cycle times and timeouts of
           the PD packets received or sent.
           If we need to poll something faster than the lowest PD cycle,
           we need to set the maximum time out our self.
         */
        if (vos_cmpTime(&tv, &max_tv) > 0)
        {
            tv = max_tv;
        }
        else if (vos_cmpTime(&tv, &min_tv) < 0)
        {
            tv = min_tv;
        }

        /*
           Select() will wait for ready descriptors or time out,
           what ever comes first.
         */
        rv = vos_select(noDesc + 1, &rfds, NULL, NULL, &tv);

        /*
           Check for overdue PDs (sending and receiving)
           Send any pending PDs if it's time...
           Detect missing PDs...
           'rv' will be updated to show the handled events, if there are
           more than one...
           The callback function will be called from within the tlc_process
           function (in it's context and thread)!
         */
        tlc_process(appHandle, &rfds, &rv);

        /* Handle other ready descriptors... */
        if (rv > 0)
        {
            printf("other descriptors were ready\n");
        }
        else
        {
            printf(".");
            fflush(stdout);
        }
        
        cfg_file = fopen(CONFIG_FILE,"r");
        if (cfg_file)
        {
            fscanf(cfg_file,"E:%d\nO:%d\nC:%d\nT:%d", &etbTopoCnt, &opTrnTopoCnt,&ownOpCstNo_32,&ownTrnCstNo_32);
            ownOpCstNo = (UINT8) ownOpCstNo_32;
            ownTrnCstNo = (UINT8) ownTrnCstNo_32;
            if (etbTopoCnt_old != etbTopoCnt || opTrnTopoCnt != opTrnTopoCnt_old || 
                ownOpCstNo_old != ownOpCstNo || ownTrnCstNo_old != ownTrnCstNo){
                printf("\nCfgFile NEW : EtbTopoCount=%u OpTrainTopocount=%u ownOpCstNo=%u ownTrnCstNo=%u\n",
                etbTopoCnt, opTrnTopoCnt,ownOpCstNo,ownTrnCstNo);
                etbTopoCnt_old = etbTopoCnt;
                opTrnTopoCnt_old = opTrnTopoCnt;
                ownOpCstNo_old = ownOpCstNo;
                ownTrnCstNo_old = ownTrnCstNo;
            }
            fclose(cfg_file);
        }

        if (setup_tti_data(appHandle, etbTopoCnt, opTrnTopoCnt, ownOpCstNo, ownTrnCstNo, pTelegram)){
            printf("setup_tti_data error\n");
            rv = 1;
            break;
        } else {
            err = tlp_put(appHandle, pubHandle, data, sizeof(TRDP_OP_TRAIN_DIR_STATUS_INFO_T));
            if (err != TRDP_NO_ERR)
            {
                printf("put pd error\n");
                rv = 1;
                break;
            }
        }
    }

    /*
     *    We always clean up behind us!
     */
    tlp_unpublish(appHandle, pubHandle);
    tlc_closeSession(appHandle);
    tlc_terminate();
    if (cfg_file){
        fclose(cfg_file);
    }
    return rv;
}
