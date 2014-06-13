/*
 * SMS WEB SERVICE
 */

#include <arpa/inet.h>
#include <unistd.h>

#include <curl/curl.h>

#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjsip_ua.h>

#include "list.h"

/*********
 * UTILS *
 *********/

#define MSISDN_LENGTH		15
#define TEXT_LENGTH		1024
#define SMSC_LENGTH		10
#define FID_LENGTH		255

#define DELIVERY_SUCCESS	1
#define DELIVERY_FAILURE	2
#define MESSAGE_BUFFERED	4
#define SMSC_SUBMIT 		8
#define SMSC_REJECT		16

#define DLR_404		"NACK/0x0000000b/Invalid+Destination+Address"
#define DLR_410         "NACK/0x000000fe/Transaction+Delivery+Failure"

struct sms {
	char from[MSISDN_LENGTH];		/* SMS sender */
	char to[MSISDN_LENGTH];			/* SMS receiver */
	char text[TEXT_LENGTH];			/* SMS text */
	char orig_smsc[SMSC_LENGTH];		/* originating SMSC */
	char dest_smsc[SMSC_LENGTH];		/* destination SMSC */
};

struct dlr {
	int type;                               /* DLR type */
	char cause[255];			/* DLR textual cause (akc/nack) */
        char to[MSISDN_LENGTH];			/* SMS receiver */
	char fid[FID_LENGTH];                   /* foreign message ID */
	char metadata[255];			/* optional TLV metadata */
};

static void headers(int client);
//static void accepted(int client);
static void bad_request(int client);
static void not_found(int client);
static void cannot_execute(int client);
static void unimplemented(int client);

static int send_to_kannel(struct sms *sms, unsigned ref);
//static int send_dlr_to_kannel(int dlr_state, char *fid, char *to);

char *strstrtok(char *str, char *delim)
{
    static char *prev;
    if (!str) str = prev;
    if (str) {
        char *end = strstr(str, delim);
        if (end) {
            prev = end + strlen(delim);
            *end = 0;
        } else {
            prev = 0;
        }
    }
    return str;
}

/*****************
 * SIP INTERFACE *
 *****************/

#define THIS_FILE 	"sms_ws.c"
#define LOCAL_ADDRESS 	"193.169.138.177"
#define SIP_PORT 	6060
//#define PRX_DOMAIN 	"devprx01.speakup.nl:5065;transport=udp"
#define PRX_DOMAIN      "193.169.138.177:7070"

#define CID_DELIMITERS	"! \n"

#define TOTAG_LENGTH	8

/* memory stuffs */
static pj_caching_pool cp;

/* threading */
pj_pool_t *sip_pool;
pj_pool_t *threads_pool;

/* mutex */
pj_pool_t *mutex_pool;
pj_mutex_t *sip_mutex;

/* SIP endpoint */
static pjsip_endpoint *sip_endpt;

/* SMS session list */
LIST_HEAD(sms_session_list);
static int g_callref = 0;

/* SMS session */
struct sms_session
{
	/* linux list entry */
	struct list_head entry;

	/* reference number */
	unsigned ref;

	/* Kannel client FD */
	int client;

	/* SIP stuffs */
	pj_pool_t *pool;
    	pjsip_transaction *tsx;		/* UAS/UAC transaction */
	pjsip_tx_data *uas_tdata;	/* tx data buffer (only for UAS) */
};

/* Create an SMS session */
static struct sms_session *create_session(void)
{
	struct sms_session *s;
	pj_pool_t *pool;

	pj_mutex_lock(sip_mutex);

	PJ_LOG(4,(THIS_FILE, "create session"));

	// INIT SMS SESSION POOL
	pool = pj_pool_create(&cp.factory, NULL, 1000, 1000, NULL);
	if (!pool) {
		pj_mutex_unlock(sip_mutex);
		return NULL;
	}

        // INIT SMS SESSION STRUCTURE
        s = pj_pool_zalloc(pool, sizeof(struct sms_session));
        list_add_tail(&s->entry, &sms_session_list);
	s->pool = pool;
	s->ref = g_callref++;

	pj_mutex_unlock(sip_mutex);
	return s;
}

/* Find an SMS session */
static struct sms_session *find_session(unsigned ref)
{
	struct sms_session *s;

	pj_mutex_lock(sip_mutex);

	list_for_each_entry(s, &sms_session_list, entry) {
		if (s->ref == ref) {
			PJ_LOG(5,(THIS_FILE, "session found"));
			pj_mutex_unlock(sip_mutex);
			return s;
		}
	}

	PJ_LOG(4,(THIS_FILE, "session not found"));

	pj_mutex_unlock(sip_mutex);
	return NULL;
}

/* Destroy an SMS session */
static void destroy_session(struct sms_session *s)
{
	pj_mutex_lock(sip_mutex);

	// safety
	if (!s) return;

	PJ_LOG(4,(THIS_FILE, "destroy session"));

	list_del(&s->entry);

	if (s->pool)
		pj_pool_release(s->pool);
	s = NULL;

	pj_mutex_unlock(sip_mutex);
	return;
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

    	PJ_CHECK_STACK();

    	pj_strerror(rc, errbuf, sizeof(errbuf));
    	PJ_LOG(1,(THIS_FILE, "%s: [pj_status_t=%d] %s", msg, rc, errbuf));
}

/*static int init_pj_thread(void)
{
	pj_thread_desc desc;
	pj_thread_t *this_thread;
	pj_status_t status;

	pj_bzero(desc, sizeof(desc));
	status = pj_thread_register(NULL, desc, &this_thread);
	if (status != PJ_SUCCESS) {
		app_perror("error in pj_thread_register", status);
		return 0;
	}

	return 1;
}*/

/* Callback to be called when transaction session's state has changed */
static void tsx_state_changed(pjsip_transaction *tsx, pjsip_event *e)
{
	PJ_UNUSED_ARG(e);

	struct sms_session *session = tsx->mod_data[mod_sip_tsx.id];
	if (!session)
		return;

	PJ_LOG(4,(THIS_FILE, "tsx state changes (new state->%d)", tsx->state));

	if (tsx->role == PJSIP_ROLE_UAS) {
		if (tsx->state == PJSIP_TSX_STATE_COMPLETED
		   || tsx->state == PJSIP_TSX_STATE_CONFIRMED)
		{
			PJ_LOG(3,(THIS_FILE, "[%u] UAS state CONFIRMED (%d)", session->ref, tsx->status_code));

			if (tsx->status_code == 200)
				headers(session->client);
			else
				cannot_execute(session->client);

		} else if (tsx->state == PJSIP_TSX_STATE_TERMINATED) {

			PJ_LOG(3,(THIS_FILE, "[%u] UAS state TERMINATED", session->ref));

			destroy_session(session);

		}

	} else {
		if (tsx->state == PJSIP_TSX_STATE_COMPLETED) {

			PJ_LOG(3,(THIS_FILE, "[%u] UAC state COMPLETED (%d)", session->ref, tsx->status_code));

			if (tsx->status_code == 200)
				headers(session->client);
                        else
                                cannot_execute(session->client);


		} else if (tsx->state == PJSIP_TSX_STATE_TERMINATED) {

			PJ_LOG(3,(THIS_FILE, "[%u] UAC state TERMINATED", session->ref));

                        destroy_session(session);

		}
	}

}

static void parse_prx_request(pjsip_rx_data *rdata, struct sms *sms)
{
	PJ_LOG(4,(THIS_FILE, "parse proxy request"));

	pjsip_sip_uri *from_uri, *to_uri;

	from_uri = pjsip_uri_get_uri(rdata->msg_info.from->uri);
	char *from = strtok((char*)pj_strbuf(&from_uri->user), "@");
        strncpy(sms->from, from, MSISDN_LENGTH);

	to_uri = pjsip_uri_get_uri(rdata->msg_info.to->uri);
        char *to = strtok((char*)pj_strbuf(&to_uri->user), "@");
        strncpy(sms->to, to, MSISDN_LENGTH);

	const pj_str_t HNAME = { "X-SpeakUp-Carrier-Select", 24 };
	pjsip_generic_string_hdr *x_carr = NULL;
	x_carr = (pjsip_generic_string_hdr*)
              pjsip_msg_find_hdr_by_name(rdata->msg_info.msg, &HNAME, x_carr);
	if (x_carr) {
		char *d_smsc = (char*)pj_strbuf(&x_carr->hvalue);
		char *d_smsc_chop = strtok(d_smsc, "\n");
		unsigned len = (unsigned)strlen(d_smsc_chop);
		d_smsc_chop[len-1] = '\0';
		strncpy(sms->dest_smsc, d_smsc_chop, SMSC_LENGTH);
	}

	unsigned len = rdata->msg_info.msg->body->len;
	char *text = (char *)rdata->msg_info.msg->body->data;
        text[len] = '\0';
        strncpy(sms->text, text, len+1);
}

static void generate_totag(char *totag)
{
	char *sc = "abcdefghijklmnopqrstuvwxyz123456789";
	int sc_len = strlen(sc);

	int i;
	for (i = 0; i < TOTAG_LENGTH; i++)
		totag[i] = sc[rand() % sc_len];

	totag[TOTAG_LENGTH] = '\0';
	return;
}

static void process_proxy_request(pjsip_rx_data *rdata)
{
	PJ_LOG(4,(THIS_FILE, "process proxy request"));

    	struct sms_session *session;
	struct sms sms;
    	pj_status_t status;
	pj_str_t reason, cid, totag;
	pjsip_tx_data *tdata;
	char totag_c[TOTAG_LENGTH];
	int http_code;

	// CREATE SESSION
	if (!(session = create_session())) {
		reason = pj_str("Failed to create a session");
                goto internal_error_stateless;
        }

	// CREATE UAS TRANSACTION SESSION
    	status = pjsip_tsx_create_uas(&mod_sip_tsx, rdata, &session->tsx);
    	if (status != PJ_SUCCESS) {
		reason = pj_str("Failed to create UAS transaction");
	    	goto internal_error_stateless;
    	}

	// DRIVE UAS TRANSACTION STATE OUT OF NULL
	pjsip_tsx_recv_msg(session->tsx, rdata);

    	// ATTACH SESSION DATA TO TRANSACTION SESSION
    	session->tsx->mod_data[mod_sip_tsx.id] = (void *)session;

	// GENERATE RANDOM TO TAG
        generate_totag(totag_c);
	totag = pj_str(totag_c);
	pj_strdup(session->pool, &rdata->msg_info.to->tag, &totag);

	// PRINT CALL-ID
	cid = rdata->msg_info.cid->id;
	char *call_id = strtok((char*)pj_strbuf(&cid), CID_DELIMITERS);
	PJ_LOG(3,(THIS_FILE, "[%u] ***Call-ID*** %s", session->ref, call_id));

	// PARSE PROXY REQUEST
	parse_prx_request(rdata, &sms);
	PJ_LOG(3,(THIS_FILE, "[%u] Dest SMSC %s", session->ref, sms.dest_smsc));

	// SEND SMS TO KANNEL
	http_code = send_to_kannel(&sms, session->ref);
	if (!http_code) {
		reason = pj_str("Unable to send SMS to Kannel");
		goto internal_error_stateful;
	}
	// ACCEPTED FOR DELIVERY | QUEUED FOR LATER DELIVERY
	if (http_code == 202) {
		// CREATE 100 TRYING RESPONSE
        	status = pjsip_endpt_create_response(sip_endpt, rdata, 100, NULL, &tdata);
	        if (status != PJ_SUCCESS) {
        	        reason = pj_str("Failed to create 100 TRYING response");
                	goto internal_error_stateful;
        	}
		// SEND 100 TRYING RESPONSE
		status = pjsip_tsx_send_msg(session->tsx, tdata);
	        if (status != PJ_SUCCESS) {
                	reason = pj_str("Failed to send response to the proxy");
                	goto internal_error_stateful;
        	}
		http_code = 200;
	}

	// CREATE DLR RESPONSE IN ADVANCE
        status = pjsip_endpt_create_response(sip_endpt, rdata, http_code,
	        				NULL, &session->uas_tdata);
        if (status != PJ_SUCCESS) {
        	reason = pj_str("Failed to create response");
                goto internal_error_stateful;
        }

	// DONE
	return;

internal_error_stateless:
	// RESPOND WITH 500 (Internal Server Error)
	PJ_LOG(3,(THIS_FILE, "Internal error (reason: %s)", pj_strbuf(&reason)));
        pjsip_endpt_respond_stateless(sip_endpt, rdata, 500, &reason, NULL, NULL);
	return;

internal_error_stateful:
        // RESPOND WITH 500 (Internal Server Error)
        PJ_LOG(3,(THIS_FILE, "[%u] Internal error (reason: %s)",
				session->ref, pj_strbuf(&reason)));
        pjsip_endpt_create_response(sip_endpt, rdata, 200, &reason, &tdata);
	pjsip_tsx_send_msg(session->tsx, tdata);
        return;
}

static pj_bool_t rx_request(pjsip_rx_data *rdata)
{
	PJ_LOG(4,(THIS_FILE, "rx request"));

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
    	process_proxy_request(rdata);

    	// DONE
    	return PJ_TRUE;
}

static int handle_sms(struct sms *sms, int client)
{
    	pjsip_tx_data *tdata;
    	pj_status_t status;
	pj_str_t target, from, text;
	char target_c[255], from_c[255];
	struct sms_session *session;

	// CREATE REQUEST MESSAGE
	sprintf(target_c, "sip:%s@%s", sms->to, PRX_DOMAIN);
    	sprintf(from_c, "sip:%s@%s:%d", sms->from, LOCAL_ADDRESS, SIP_PORT);

	target = pj_str(target_c);
	from = pj_str(from_c);
	text = pj_str(sms->text);

    	status = pjsip_endpt_create_request(sip_endpt, &pjsip_message_method, &target,
					&from, &target, NULL, NULL, -1, &text, &tdata);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to create request message", status);
		return 0;
    	}
	//FIXME
	pjsip_generic_string_hdr x_carr;
        pj_str_t hname = pj_str("X-SpeakUp-TrunkType");
        pj_str_t hvalue = pj_str("airtime");
        pjsip_generic_string_hdr_init2(&x_carr, &hname, &hvalue);
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)&x_carr);

	// CREATE SESSION
        if (!(session = create_session())) {
                app_perror("Failed to create session", PJ_EUNKNOWN);
                return 0;
        }
	session->client = client;

    	// CREATE UAC TRANSACTION TO SEND THE REQUEST
    	status = pjsip_tsx_create_uac(&mod_sip_tsx, tdata, &session->tsx);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to create UAC transaction", status);
		destroy_session(session);
		return 0;
    	}

	// ATTACH SESSION DATA TO UAC TRANSACTION
        session->tsx->mod_data[mod_sip_tsx.id] = (void *)session;

	// PRINT CALL-ID
	/*const pj_str_t HNAME = { "Call-ID", 7 };
        pjsip_generic_string_hdr *cid_h = NULL;
        cid_h = (pjsip_generic_string_hdr*)
              pjsip_msg_find_hdr_by_name(tdata->msg, &HNAME, cid_h);
        if (cid_h) {
		char *call_id = strtok((char*)pj_strbuf(&cid_h->hvalue), CID_DELIMITERS);
        	PJ_LOG(3,(THIS_FILE, "[%u] ***Call-ID*** %s", session->ref, call_id));
        }*/

	PJ_LOG(3,(THIS_FILE, "[%u] SMS: from=%s, to=%s, text=%s, orig_smsc=%s",
                session->ref, sms->from, sms->to, sms->text, sms->orig_smsc));

	// SEND REQUEST MESSAGE
    	status = pjsip_tsx_send_msg(session->tsx, tdata);
    	if (status != PJ_SUCCESS) {
		app_perror("Failed to send request message", status);
	        pjsip_tx_data_dec_ref(tdata); /* Destroy transmit data */
		pjsip_tsx_terminate(session->tsx, PJSIP_SC_INTERNAL_SERVER_ERROR);
		return 0;
	}

	return 1;
}

static int handle_dlr(struct dlr *dlr, int client, unsigned ref)
{
	pj_status_t status;
	int status_code;
	struct sms_session *session;

	PJ_LOG(4,(THIS_FILE, "handle DLR"));

	if (!(session = find_session(ref))) {
		app_perror("Failed to find session", PJ_ENOTFOUND);
                return 0;
        }
	session->client = client;

	PJ_LOG(3,(THIS_FILE, "[%u] DLR: type=%d", session->ref, dlr->type));

	switch (dlr->type) {
	case DELIVERY_SUCCESS:
		status_code = 200;
		break;
	case DELIVERY_FAILURE:
		/* fixme: parse metadata */
		status_code = 480;
		break;
	case MESSAGE_BUFFERED:
	case SMSC_SUBMIT:
		return 1; //should I update proxy state here?
	case SMSC_REJECT:
		if (!strcmp(dlr->cause, DLR_404)) {
                        status_code = 404;
                        break;
                }
		if (!strcmp(dlr->cause, DLR_410)) {
			status_code = 410;
			break;
		}
		status_code = 404; //FIXME
		break;
	default:
		goto internal_error;
	}

	// UPDATE RESPONSE
	session->uas_tdata->msg->line.status.code = status_code;

	// SEND RESPONSE
	PJ_LOG(3,(THIS_FILE, "send %d response to the proxy", status_code));
        status = pjsip_tsx_send_msg(session->tsx, session->uas_tdata);
        if (status != PJ_SUCCESS)
                goto internal_error;

	return 1;

internal_error:
	// RESPOND WITH 500 (Internal Server Error)
	PJ_LOG(3,(THIS_FILE, "[%u] Internal Server Error", session->ref));
	session->uas_tdata->msg->line.status.code = 500;
	pjsip_tsx_send_msg(session->tsx, session->uas_tdata);
        return 0;

}

static int accept_sip_requests(void *arg)
{
	PJ_UNUSED_ARG(arg);

	while (1) {
                pj_time_val delay = {0, 10};
                pjsip_endpt_handle_events(sip_endpt, &delay);
        }

	return 0;
}

/* Init SIP stack */
static int init_sip(void)
{
        pj_status_t status;

        /* SET LOGGING LEVEL
	 * 3 = minimal
	 * 4 = debug */
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

	// INIT THREAD POOL
	threads_pool = pj_pool_create(&cp.factory, "http_threads", 1000, 1000, NULL);
	if (!threads_pool) {
                app_perror("Failed to create SIP threads pool", PJ_ENOMEM);
                return 0;
        }

	sip_pool = pj_pool_create(&cp.factory, "sip_threads", 1000, 1000, NULL);
        if (!sip_pool) {
                app_perror("Failed to create SIP threads pool", PJ_ENOMEM);
                return 0;
        }

	// INIT MUTEX POOL
        mutex_pool = pj_pool_create(&cp.factory, "mutex", 1000, 1000, NULL);
        if (!mutex_pool) {
		app_perror("Failed to create mutex pool", PJ_ENOMEM);
                return 0;
	}

	// CREATE MUTEX
	status = pj_mutex_create(mutex_pool, "", PJ_MUTEX_SIMPLE, &sip_mutex);
    	if (status != PJ_SUCCESS) {
        	app_perror("Failed to create mutex", status);
        	return 0;
    	}

        // CREATE ENDPOINT
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

                PJ_LOG(1,(THIS_FILE, "SIP UDP listening on %.*s:%d",
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

/******************
 * HTTP INTERFACE *
 ******************/

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: Kannel/1.4.3\r\n"
#define SERVER_HOST "193.169.138.177:13013"
#define DLR_SERVER_HOST "193.169.138.177:13015"

#define SENDSMS_REQUEST "/cgi-bin/sendsms?username=spup&password=spup&from=%s&to=%s&text=%s&smsc=%s&dlr-mask=19&dlr-url="
#define DLR_URL "http://193.169.138.177:50000/dlr?type=%d&cause=%A&fid=%F&to=%p&meta-data=%D&ref="

/* 200 OK message */
static void headers(int client)
{
	//DEBUG
        //printf("200 OK  %d\n", client);

 	char buf[1024];

	if (!client)
		return; //paranoid

 	sprintf(buf, "HTTP/1.0 200 OK\r\n");
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
        send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>Ok.\r\n");
	send(client, buf, strlen(buf), 0);

	// CLOSE CLIENT SOCKET
        shutdown(client, SHUT_RDWR);
        close(client);
}

/* 202 Accepted message */
/*static void accepted(int client)
{
	//DEBUG
        //printf("202 ACCEPTED  %d\n", client);

	char buf[1024];

	if (!client)
                return; //paranoid

	sprintf(buf, "HTTP/1.0 202 Accepted\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>Accepted request.\r\n");
	send(client, buf, strlen(buf), 0);
}*/

/* 400 Bad Request message */
static void bad_request(int client)
{
	//DEBUG
        //printf("400 BAD REQUEST  %d\n", client);

	char buf[1024];

	if (!client)
                return; //paranoid

	sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>Wrong request.\r\n");
	send(client, buf, strlen(buf), 0);

	// CLOSE CLIENT SOCKET
        shutdown(client, SHUT_RDWR);
        close(client);
}

/* 404 Not Found message. */
static void not_found(int client)
{
	//DEBUG
        //printf("404 NOT FOUND  %d\n", client);

	char buf[1024];

	if (!client)
                return; //paranoid

	sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, SERVER_STRING);
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-Type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>The server could not fulfill\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "your request because the resource specified\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "is unavailable or nonexistent.\r\n");
	send(client, buf, strlen(buf), 0);

	// CLOSE CLIENT SOCKET
        shutdown(client, SHUT_RDWR);
        close(client);
}

/* 500 Internal Server Error message */
static void cannot_execute(int client)
{
	//DEBUG
        //printf("500 INTERNAL SERVER ERROR  %d\n", client);

	char buf[1024];

	if (!client)
                return; //paranoid

	sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "Content-type: text/html\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "\r\n");
	send(client, buf, strlen(buf), 0);
	sprintf(buf, "<P>Error executing the SMS request.\r\n");
	send(client, buf, strlen(buf), 0);

	// CLOSE CLIENT SOCKET
        shutdown(client, SHUT_RDWR);
        close(client);
}

/* 501 Method Not Implemented */
static void unimplemented(int client)
{
	//DEBUG
        //printf("501 METHOD NOT IMPLEMENTED  %d\n", client);

 	char buf[1024];

	if (!client)
                return; //paranoid

	sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
	send(client, buf, strlen(buf), 0);
 	sprintf(buf, SERVER_STRING);
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, "Content-Type: text/html\r\n");
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, "\r\n");
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, "</TITLE></HEAD>\r\n");
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
 	send(client, buf, strlen(buf), 0);
 	sprintf(buf, "</BODY></HTML>\r\n");
 	send(client, buf, strlen(buf), 0);

	// CLOSE CLIENT SOCKET
        shutdown(client, SHUT_RDWR);
        close(client);
}

/* Print out an error message with perror()
 * and exit the program indicating an error */
static void error_die(const char *sc)
{
 	perror(sc);
 	exit(1);
}

/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character. */
static int get_line(int sock, char *buf, int size)
{
 	int i = 0;
 	char c = '\0';
 	int n;

 	while ((i < size - 1) && (c != '\n')) {
  		n = recv(sock, &c, 1, 0);
  		/* DEBUG printf("%02X\n", c); */
  		if (n > 0) {
   			if (c == '\r') {
    				n = recv(sock, &c, 1, MSG_PEEK);
    				/* DEBUG printf("%02X\n", c); */
    				if ((n > 0) && (c == '\n'))
     					recv(sock, &c, 1, 0);
    				else
     					c = '\n';
   			}
   			buf[i] = c;
   			i++;
  		}
  		else
   			c = '\n';
 	}
	buf[i] = '\0';

	return(i);
}

/* parse and process incoming HTTP request */
static int accept_http_request(int client)
{
	struct sms sms;
	struct dlr dlr;
	unsigned ref;
        char buf[1024], method[255], url[255];

	// PARSE INCOMING REQUEST
        if (get_line(client, buf, sizeof(buf)) > 0) {
                size_t i = 0, j = 0;

		// EXTRACT HTTP METHOD
                while (!ISspace(buf[j]) && (i < sizeof(method) -1)) {
                        method[i] = buf[j];
                        i++; j++;
                }
                method[i] = '\0';

		// DON'T FORGET THE SPACES
                i = 0;
                while (ISspace(buf[j]) && (j < sizeof(buf)))
                        j++;

		//EXTRACT URL
                while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf))) {
                        url[i] = buf[j];
                        i++; j++;
                }
                url[i] = '\0';
        }
        else {
                bad_request(client);
                return 0;
        }

	// WE ONLY PROCESS GET REQUESTS
        if (strcasecmp(method, "GET") == 0) {
		char *service, *token;

		service = strstrtok(url, "?");
		if (!service) {
			bad_request(client);
                        return 0;
                }
		if (!strcmp(service, "/dlr")) {
			// DLR TYPE
			token = strstrtok(NULL, "type=");
			token = strstrtok(NULL, "&");
			if (!token) {
                                bad_request(client);
                                return 0;
                        }
			dlr.type = atoi(token);
			// DLR CAUSE
			token = strstrtok(NULL, "cause=");
                        token = strstrtok(NULL, "&");
                        if (!token) {
                                bad_request(client);
                                return 0;
                        }
                        strncpy(dlr.cause, curl_unescape(token, 0), sizeof(dlr.cause));
			// FOREIGN MSG ID
			token = strstrtok(NULL, "fid=");
			token = strstrtok(NULL, "&");
                        if (!token) {
                                bad_request(client);
                                return 0;
                        }
			strncpy(dlr.fid, curl_unescape(token, 0), FID_LENGTH);
			// TO
                        token = strstrtok(NULL, "to=");
                        token = strstrtok(NULL, "&");
                        if (!token) {
                                bad_request(client);
                                return 0;
                        }
			strncpy(dlr.to, token, MSISDN_LENGTH);
			// META-DATA
                        token = strstrtok(NULL, "meta-data=");
                        token = strstrtok(NULL, "&");
                        if (!token) {
                                bad_request(client);
                                return 0;
                        }
                        strncpy(dlr.metadata, curl_unescape(token, 0), sizeof(dlr.metadata));
			// REF
			token = strstrtok(NULL, "ref=");
			token = strstrtok(NULL, "&");
                        if (!token) {
                                bad_request(client);
                                return 0;
                        }
                        ref = atoi(token);
			// HANDLE DELIVERY REPORT
			if (!handle_dlr(&dlr, client, ref))
				cannot_execute(client); //HTTP 500
		}
		else if (!strcmp(service, "/sms")) {
			// TO
			token = strstrtok(NULL, "to=");
			token = strstrtok(NULL, "&");
        	        if (!token) {
                	        bad_request(client);
                        	return 0;
	                }
        	        strncpy(sms.to, token, MSISDN_LENGTH);
			// TEXT
			token = strstrtok(NULL, "text=");
                        token = strstrtok(NULL, "&");
                        if (!token) {
                                bad_request(client);
                                return 0;
                        }
                        strncpy(sms.text, curl_unescape(token, 0), TEXT_LENGTH);
			// FROM
			token = strstrtok(NULL, "from=");
                	token = strstrtok(NULL, "&");
	                if (!token) {
        	                bad_request(client);
                	        return 0;
	                }
        	        strncpy(sms.from, token, MSISDN_LENGTH);
			// ORIGIN SMSC
			token = strstrtok(NULL, "smsc=");
                	token = strstrtok(NULL, "&");
	                if (!token) {
        	                bad_request(client);
                	        return 0;
	                }
        	        strncpy(sms.orig_smsc, token, SMSC_LENGTH);
			// HANDLE INCOMING SMS
			if (!handle_sms(&sms, client))
				cannot_execute(client); //HTTP 500
	        }
		else
			// WRONG ACTION
			not_found(client);
	}
        else
		// WRONG METHOD
               	unimplemented(client);

	return 0;
}

/* Send SMS to Kannel */
static int send_to_kannel(struct sms *sms, unsigned ref)
{
        CURL *curl;
        CURLcode res;
	char buf[2048], sendsms[1024], dlr_url[1024];
	int rc = 1;

	// CREATE SENDSMS REQUEST
        sprintf(sendsms, SENDSMS_REQUEST, sms->from, sms->to, curl_escape(sms->text, 0), sms->dest_smsc);
	//printf("sendsms request: %s\n", sendsms); //DEBUG

	// CREATE DLR URL
        sprintf(dlr_url, "%s%u", DLR_URL, ref);
	//printf("%s\n", dlr_url); //DEBUG

	// UNITE THEM TO FORM KANNEL'S HTTP REQUEST
        sprintf(buf, "%s%s%s", SERVER_HOST, sendsms, curl_escape(dlr_url, 0));

	// SEND THE REQUEST
        curl = curl_easy_init();
        if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, buf);

                res = curl_easy_perform(curl);

                if (res != CURLE_OK) {
			rc = 0;
                        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                                curl_easy_strerror(res));
			goto out;
		}

		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		rc = http_code;

	out:
                curl_easy_cleanup(curl);
		printf("  (%d) \n", rc);
        }

        return rc;
}

/*static int send_dlr_to_kannel(int state, char *fid, char *to)
{
        CURL *curl;
        CURLcode res;
        char buf[1024];
     	int rc = 1;

        // CREATE DLR FOR KANNEL
        sprintf(buf, "%s/sms?username=spup&password=spup&dlr-mask=%d&dlr-mid=%s&to=%s&smsc=pgsm",
							DLR_SERVER_HOST, state, fid, to);

	printf("dlr-url %s\n", buf);

        // SEND THE REQUEST
        curl = curl_easy_init();
        if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, buf);

                res = curl_easy_perform(curl);

                if (res != CURLE_OK) {
                        rc = 0;
                        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                                curl_easy_strerror(res));
                }

                curl_easy_cleanup(curl);
                printf("\n");
        }

        return rc;
}*/

/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, dynamically allocate one
 */
static int startup(u_short *port)
{
 	int httpd = 0;
 	struct sockaddr_in name;

 	httpd = socket(PF_INET, SOCK_STREAM, 0);
 	if (httpd == -1)
  		error_die("socket");
 	memset(&name, 0, sizeof(name));
 	name.sin_family = AF_INET;
 	name.sin_port = htons(*port);
 	name.sin_addr.s_addr = htonl(INADDR_ANY);
 	if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
  		error_die("bind");
 	if (*port == 0) {
  		socklen_t namelen = sizeof(name);
  		if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
   			error_die("getsockname");
  		*port = ntohs(name.sin_port);
 	}
 	if (listen(httpd, 5) < 0)
  		error_die("listen");
 	return(httpd);
}

int main(void)
{
 	int server_sock = -1;
 	u_short port = 50000;
 	int client_sock = -1;
 	struct sockaddr_in client_name;
 	socklen_t client_name_len = sizeof(client_name);

	if (!init_sip()) {
		perror("cannot init sip iface\n");
		return 0;
	}

	pj_thread_t *sip_thread;
	pj_thread_create(sip_pool, "sip_thread", &accept_sip_requests, NULL,
				  0, 0, &sip_thread);

	server_sock = startup(&port);
        printf("httpd running on port %d\n", port);

 	while (1) {
  		client_sock = accept(server_sock,
                        (struct sockaddr *)&client_name,
                        &client_name_len);
  		if (client_sock == -1)
   			error_die("accept");
		pj_thread_t *http_thread;
        	pj_thread_create(threads_pool, "http_thread", &accept_http_request,
					client_sock, 0, 0, &http_thread);
 	}

 	close(server_sock);
	destroy_sip();

 	return 0;
}
