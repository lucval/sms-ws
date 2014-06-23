/*
 * SMS WEB SERVICE
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <curl/curl.h>

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjsip_ua.h>

#include "list.h"

/*********
 * UTILS *
 *********/

#define TIMESTAMP_LENGTH	10
#define MSISDN_LENGTH		15
#define TEXT_LENGTH		1024
#define SMSC_LENGTH		256
#define ID_LENGTH 		1024

struct sms {
	char ts[TIMESTAMP_LENGTH];		/* sms tx timestamp in UNIX epoch */
	char from[MSISDN_LENGTH];		/* sms sender */
	char to[MSISDN_LENGTH];			/* sms receiver */
	char text[TEXT_LENGTH];			/* sms text */
	char orig_smsc[SMSC_LENGTH];		/* originating SMSC */
	char dest_smsc[SMSC_LENGTH];		/* destination SMSC */
};

static int handle_sms(struct sms *sms);

/*****************
 * SIP INTERFACE *
 *****************/

#define THIS_FILE 	"prx_emu.c"
#define LOCAL_ADDRESS 	"193.169.138.177"
#define SIP_PORT 	7070
#define APP_DOMAIN 	"193.169.138.177:6060"

/* memory stuffs */
static pj_caching_pool cp;

/* SIP endpoint */
static pjsip_endpoint *sip_endpt;

/* SMS session list */
LIST_HEAD(sms_session_list);

enum session_state {
        MO_DELIVERED = 1,
	MT_RECEIVED = 2,
        SUCCESS = 3,
};

/* SMS session */
struct sms_session
{
	/* linux list entry */
	struct list_head entry;

	/* unique ID */
	char id[ID_LENGTH];

	/* state */
	int state;

	/* SIP stuffs */
	pj_pool_t *pool;
    	pjsip_transaction *tsx;		/* UAS/UAC transaction */
	pjsip_rx_data *uas_rdata;	/* rx data buffer (for UAS only) */
   	pj_timer_entry d_timer;		/* Disconnect timer */
};

/* Create an SMS session */
static struct sms_session *create_session(void)
{
	struct sms_session *s;
	pj_pool_t *pool;

	// INIT SMS SESSION POOL
	pool = pj_pool_create(&cp.factory, NULL, 1000, 1000, NULL);
	if (!pool)
		return NULL;

        // INIT SMS SESSION STRUCTURE
        s = pj_pool_zalloc(pool, sizeof(struct sms_session));
        list_add_tail(&s->entry, &sms_session_list);
	s->pool = pool;

	return s;
}

/* Find an SMS session */
static struct sms_session *find_session(char *id)
{
	struct sms_session *s;

	list_for_each_entry(s, &sms_session_list, entry) {
		if (!(strcmp(s->id, id)))
			return s;
	}

	return NULL;

}

/* Destroy an SMS session */
static void destroy_session(struct sms_session *s)
{
	list_del(&s->entry);

	if (s->pool) {
		pj_pool_release(s->pool);
		s->pool = NULL;
	}

	s = NULL;
}

/* Declare MESSAGE method */
enum
{
    PJSIP_MESSAGE_METHOD = PJSIP_OTHER_METHOD
};

const pjsip_method pjsip_message_method =
{
    PJSIP_MESSAGE_METHOD,
    { "MESSAGE", 7 }
};

/* Callback to be called to handle incoming requests outside dialogs */
static pj_bool_t rx_request(pjsip_rx_data *rdata);

/* This is a PJSIP module to be registered by application to handle
 * incoming requests from the proxy outside any dialogs/transactions */
static pjsip_module mod_sip_in =
{
    	NULL, NULL,			    	/* prev, next.		*/
    	{ "mod-sip-in", 18 },		    	/* Name.		*/
    	-1,				    	/* Id			*/
    	PJSIP_MOD_PRIORITY_UA_PROXY_LAYER, 	/* Priority		*/
    	NULL,				    	/* load()		*/
    	NULL,			    		/* start()		*/
    	NULL,			    		/* stop()		*/
    	NULL,			    		/* unload()		*/
    	&rx_request,		    		/* on_rx_request()	*/
    	NULL,			    		/* on_rx_response()	*/
    	NULL,			    		/* on_tx_request.	*/
    	NULL,			    		/* on_tx_response()	*/
    	NULL,				    	/* on_tsx_state()	*/
};

/* Callback to be called to handle transaction state changed. */
static void tsx_state_changed(pjsip_transaction *tsx, pjsip_event *event);

/* This is a PJSIP module to receive notification from
 * transaction when the transaction state has changed */
static pjsip_module mod_sip_tsx =
{
        NULL, NULL,                             /* prev, next.          */
        { "mod-sip-tsx", 20 },                  /* Name.                */
        -1,                                     /* Id                   */
        PJSIP_MOD_PRIORITY_APPLICATION,         /* Priority             */
        NULL,                                   /* load()               */
        NULL,                                   /* start()              */
        NULL,                                   /* stop()               */
        NULL,                                   /* unload()             */
        NULL,		                        /* on_rx_request()      */
        NULL,                                   /* on_rx_response()     */
        NULL,                                   /* on_tx_request.       */
        NULL,                                   /* on_tx_response()     */
        &tsx_state_changed,                     /* on_tsx_state()       */
};

/* Display error */
void app_perror(const char *msg, pj_status_t rc)
{
    	char errbuf[256];

	printf("%s\n", msg);

    	PJ_CHECK_STACK();

    	pj_strerror(rc, errbuf, sizeof(errbuf));
    	PJ_LOG(1,("test", "%s: [pj_status_t=%d] %s", msg, rc, errbuf));
}

static int init_pj_thread(void)
{
	pj_thread_desc desc;
	pj_thread_t *this_thread;
	pj_status_t status;

	pj_bzero(desc, sizeof(desc));
	status = pj_thread_register("thread", desc, &this_thread);
	if (status != PJ_SUCCESS) {
		app_perror("...error in pj_thread_register", status);
		return 0;
	}

	return 1;
}

/* Callback to be called when transaction session's state has changed */
static void tsx_state_changed(pjsip_transaction *tsx, pjsip_event *e)
{
	PJ_UNUSED_ARG(e);

	struct sms_session *session = tsx->mod_data[mod_sip_tsx.id];
	if (!session)
		return;

	//DEBUG
	PJ_LOG(1,(THIS_FILE, "tsx state changes (new state->%d)", tsx->state));

	if (tsx->role == PJSIP_ROLE_UAS) {
		if (tsx->state == PJSIP_TSX_STATE_CONFIRMED
		  || tsx->state == PJSIP_TSX_STATE_COMPLETED) {

			PJ_LOG(1,(THIS_FILE, "UAS state CONFIRMED (%d)", tsx->status_code));

			session->state = SUCCESS;

		} else if (tsx->state == PJSIP_TSX_STATE_TERMINATED) {

			PJ_LOG(1,(THIS_FILE, "UAS state TERMINATED"));

			if (session->d_timer.id != 0) {
                                pjsip_endpt_cancel_timer(sip_endpt, &session->d_timer);
                                session->d_timer.id = 0;
                        }

                        if (session->state == SUCCESS)
                                printf("terminated with session_state success\n");
                        else if (session->state == MT_RECEIVED)
                                printf("terminated with session_state received\n");

                        destroy_session(session);

		}

	} else {
		if (tsx->state == PJSIP_TSX_STATE_COMPLETED) {

			PJ_LOG(1,(THIS_FILE, "UAC state COMPLETED (%d)", tsx->status_code));

			session->state = SUCCESS;

			pjsip_tsx_terminate(tsx, 200);

		} else if (tsx->state == PJSIP_TSX_STATE_TERMINATED) {

			PJ_LOG(1,(THIS_FILE, "UAC state TERMINATED"));

			if (session->d_timer.id != 0) {
                                pjsip_endpt_cancel_timer(sip_endpt, &session->d_timer);
                                session->d_timer.id = 0;
                        }

			if (session->state == SUCCESS)
				printf("terminated with session_state success\n");
			else if (session->state == MO_DELIVERED)
				printf("terminated with session_state delivered\n");

			destroy_session(session);

		}
	}

}

static void parse_app_request(pjsip_rx_data *rdata, struct sms *sms)
{
	//DEBUG
        printf("PARSE APP REQUEST\n");

	pjsip_sip_uri *from_uri, *to_uri;

	from_uri = pjsip_uri_get_uri(rdata->msg_info.from->uri);
	char *from = strtok((char*)pj_strbuf(&from_uri->user), "@");
	strncpy(sms->from, from, MSISDN_LENGTH);

	to_uri = pjsip_uri_get_uri(rdata->msg_info.to->uri);
	char *to = strtok((char*)pj_strbuf(&to_uri->user), "@");
        strncpy(sms->to, to, MSISDN_LENGTH);

	unsigned len = rdata->msg_info.msg->body->len;
	char *text = (char *)rdata->msg_info.msg->body->data;
	text[len] = '\0';
	strncpy(sms->text, text, len+1);
}

static void process_app_request(pjsip_rx_data *rdata)
{
	//DEBUG
        printf("PROCESS APP REQUEST\n");

    	struct sms_session *session;
	pj_str_t reason, cid, fromtag;
	pjsip_tx_data *tdata;
	pj_status_t status;

	// CREATE SESSION
	if (!(session = create_session())) {
		reason = pj_str("Failed to create a session");
                goto internal_error;
        }

	// CREATE UNIQUE SESSION ID
	pj_strdup(session->pool, &cid, &rdata->msg_info.cid->id);
        pj_strdup(session->pool, &fromtag, &rdata->msg_info.from->tag);
        snprintf(session->id, ID_LENGTH, "%s-%s", pj_strbuf(&cid),
						  pj_strbuf(&fromtag));
	printf("%s\n", session->id);

	// CREATE UAS TRANSACTION SESSION
    	status = pjsip_tsx_create_uas(&mod_sip_tsx, rdata, &session->tsx);
    	if (status != PJ_SUCCESS) {
		reason = pj_str("Failed to create UAS transaction");
	    	goto internal_error;
    	}

	// DRIVE UAS TRANSACTION STATE OUT OF NULL
	pjsip_tsx_recv_msg(session->tsx, rdata);

    	// ATTACH SESSION DATA TO TRANSACTION SESSION
    	session->tsx->mod_data[mod_sip_tsx.id] = (void *)session;

	session->state = MT_RECEIVED;

	// CREATE 200 OK RESPONSE
        status = pjsip_endpt_create_response(sip_endpt, rdata, 200, NULL, &tdata);
        if (status != PJ_SUCCESS) {
                reason = pj_str("Failed to create 200 OK response");
                goto internal_error;
        }

        // SEND 200 OK RESPONSE
        status = pjsip_tsx_send_msg(session->tsx, tdata);
        if (status != PJ_SUCCESS) {
                reason = pj_str("Failed to send 200 OK response");
                goto internal_error;
        }

	struct sms sms;
        parse_app_request(rdata, &sms);
        if (!handle_sms(&sms)) {
                reason = pj_str("Unable to send SMS to app");
                goto internal_error;
        }

    	// DONE
	return;

internal_error:
	printf("%s\n", pj_strbuf(&reason));
	// RESPOND WITH 500 (Internal Server Error)
        pjsip_endpt_respond_stateless(sip_endpt, rdata,
				PJSIP_SC_INTERNAL_SERVER_ERROR,
       				&reason, NULL, NULL);
	return;
}

static pj_bool_t rx_request(pjsip_rx_data *rdata)
{
	//DEBUG
        printf("RX REQUEST\n");

	// IGNORE STRANDLED ACKs
    	if (rdata->msg_info.msg->line.req.method.id == PJSIP_ACK_METHOD)
		return PJ_FALSE;

    	// RESPOND (STATELESSY) ANY NON-MESSAGE REQUESTS WITH 500  */
    	if (rdata->msg_info.msg->line.req.method.id != PJSIP_OTHER_METHOD) {
		pj_str_t reason = pj_str("Unsupported Operation");
		pjsip_endpt_respond_stateless(sip_endpt, rdata, 500, &reason, NULL, NULL);
		return PJ_TRUE;
    	}

    	// HANDLE INCOMING MESSAGE
    	process_app_request(rdata);

    	// DONE
    	return PJ_TRUE;
}


static int handle_sms(struct sms *sms)
{
	//DEBUG
        printf("HANDLE SMS\n");

    	pjsip_tx_data *tdata;
    	pj_status_t status;
	pj_str_t target, from, text;
	char target_c[255], from_c[255];
	struct sms_session *session;

	// CREATE REQUEST MESSAGE
	sprintf(target_c, "sip:%s@%s", sms->to, APP_DOMAIN);
    	sprintf(from_c, "sip:%s@%s:%d", sms->from, LOCAL_ADDRESS, SIP_PORT);

	printf("%s\n",target_c);
	printf("%s\n",from_c);

	target = pj_str(target_c);
	from = pj_str(from_c);
	text = pj_str(sms->text);

    	status = pjsip_endpt_create_request(sip_endpt, &pjsip_message_method, &target,
					&from, &target, NULL, NULL, -1, &text, &tdata);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to create request message", status);
		return 0;
    	}

        pjsip_generic_string_hdr x_carr;
	pj_str_t hname = pj_str("X-SpeakUp-Carrier-Select");
	pj_str_t hvalue;
	if (!(strcmp(sms->to, "31632271490")) ||
	    !(strcmp(sms->to, "31632271491")) ||
            !(strcmp(sms->to, "31632271492")) ||
            !(strcmp(sms->to, "31632271493")) ||
            !(strcmp(sms->to, "31632271494")) ||
            !(strcmp(sms->to, "31632271495")) ||
            !(strcmp(sms->to, "31632271496")) ||
            !(strcmp(sms->to, "31632271497")) ||
            !(strcmp(sms->to, "31632271498")) ||
            !(strcmp(sms->to, "31632271499"))) {
		hvalue = pj_str("mcs");
	}
	else {
		hvalue = pj_str("cm");
	}
	pjsip_generic_string_hdr_init2(&x_carr, &hname, &hvalue);
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)&x_carr);

	// CREATE SESSION
        if (!(session = create_session())) {
                app_perror("Failed to create session", PJ_EUNKNOWN);
                return 0;
        }

    	// CREATE UAC TRANSACTION TO SEND THE REQUEST
    	status = pjsip_tsx_create_uac(&mod_sip_tsx, tdata, &session->tsx);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to create UAC transaction", status);
		destroy_session(session);
		return 0;
    	}

	// ATTACH SESSION DATA TO UAC TRANSACTION
        session->tsx->mod_data[mod_sip_tsx.id] = (void *)session;

	// SEND REQUEST MESSAGE
    	status = pjsip_tsx_send_msg(session->tsx, tdata);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to send request message", status);
	        pjsip_tx_data_dec_ref(tdata); /* Destroy transmit data */
		pjsip_tsx_terminate(session->tsx, PJSIP_SC_INTERNAL_SERVER_ERROR);
		destroy_session(session);
		return 0;
	}

	session->state = MO_DELIVERED;

	return 1;
}

/* Init SIP stack */
static int init_sip()
{
        pj_status_t status;

        // SET LOGGING LEVEL
        pj_log_set_level(3);

        // INIT PJLIB
        status = pj_init();
        if (status != PJ_SUCCESS) {
                app_perror("Failed to init PJLIB", status);
                return 0;
        }

        // INIT PJLIB-UTIL
        status = pjlib_util_init();
        if (status != PJ_SUCCESS) {
                app_perror("Failed to init PJLIB util", status);
                return 0;
        }

        // CREATE POOL FACTORY BEFORE ALLOCATE ANY MEMORY
        pj_caching_pool_init(&cp, &pj_pool_factory_default_policy, 0);

        // CREATE THE ENDPOINT
        status = pjsip_endpt_create(&cp.factory, pj_gethostname()->ptr, &sip_endpt);
        if (status != PJ_SUCCESS) {
               app_perror("Failed to init PJLIB", status);
               return 0;
        }

        // ADD UDP TRANSPORT
        {
                pj_sockaddr_in addr;
                pjsip_transport *tp;

                pj_bzero(&addr, sizeof(addr));
                addr.sin_family = pj_AF_INET();
                addr.sin_addr.s_addr = 0;
                addr.sin_port = pj_htons(SIP_PORT);

                status = pjsip_udp_transport_start(sip_endpt, &addr, NULL, 1, &tp);

                if (status != PJ_SUCCESS) {
                        app_perror("Unable to start UDP transport", status);
                        return 0;
                }

                PJ_LOG(3,(THIS_FILE, "SIP UDP listening on %.*s:%d",
                        (int)tp->local_name.host.slen, tp->local_name.host.ptr,
                        tp->local_name.port));
        }

	// INIT TRANSACTION LAYER
        status = pjsip_tsx_layer_init_module(sip_endpt);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to init PJSIP transaction layer", status);
                return 0;
        }

	// INIT UA LAYER
        status = pjsip_ua_init_module(sip_endpt, NULL);
        if (status != PJ_SUCCESS) {
                app_perror("Failed to init PJSIP UA module", status);
                return 0;
        }

        // REGISTER MODULE TO RECEIVE INCOMING REQUEST
        status = pjsip_endpt_register_module(sip_endpt, &mod_sip_in);
        if (status != PJ_SUCCESS) {
                app_perror("Failed to init PJLIB", status);
                return 0;
        }

	// REGISTER MODULE TO HANDLE TRANSACTION STATES
        status = pjsip_endpt_register_module(sip_endpt, &mod_sip_tsx);
        if (status != PJ_SUCCESS) {
                app_perror("Failed to init PJLIB", status);
                return 0;
        }

        // DONE
        return 1;
}

/* destroy SIP */
static void destroy_sip()
{
        if (sip_endpt) {
                pjsip_endpt_destroy(sip_endpt);
                sip_endpt = NULL;
        }

	// RELEASE EXISTENT SESSION
	struct sms_session *s;
	list_for_each_entry(s, &sms_session_list, entry)
        	destroy_session(s);

	pj_caching_pool_destroy(&cp);

        // SHUTDOWN PJLIB
        pj_shutdown();

        return;
}

int main(void)
{
	if (!init_sip()) {
                perror("cannot init sip iface\n");
                return 0;
        }

        while (1) {
        	pj_time_val delay = {0, 0};
		pjsip_endpt_handle_events(sip_endpt, &delay);
		/*struct sms sms;
		strcpy(sms.from, "31632271497");
		strcpy(sms.to, "31632271497");
		strcpy(sms.text, "cialapud");
		strcpy(sms.dest_smsc, "pgsm");
		handle_sms(&sms);
		strcpy(sms.dest_smsc, "pgsm");
		handle_sms(&sms);
		sleep(rand() % 10);*/
        }

        destroy_sip();

        return 0;
}
