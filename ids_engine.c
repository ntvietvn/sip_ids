/* 
 * Viet Nguyen @ viatelecom.com 
 */
#ifdef __cplusplus
extern "C" {
#endif
#include "ids_engine.h"
#include "raw_udp.h"
#include <time.h>
#include "tslog.h"
#include <pthread.h>
#include "tsqueue.h"
#include "dialog.h"
#include "socket.h"
#include "config.h"	
#include <zmq.h>

extern struct sockaddr_in my_ip;
extern blist	blacklist;	
extern unsigned int capture_port;
extern unsigned char stateful_enabled;
extern struct notif_t noti_cfg;
extern struct criteria_t criteria_cfg;

#define DST_EMAIL	"fclement@viatelecom.com, remi.guionie@viatelecom.com, viaexploitation@viatelecom.com"
//#define DST_EMAIL	"tuanviet.nguyen@viatelecom.com"
#define SRC_EMAIL	"sip_ids"
#define MAX_CONTENT	4096

struct email {
	char *subject;
	char *content;
};

static void sendmail(void *args) {
	if (!args) return;
	char *subject = ((struct email*)args)->subject;
	char * content = ((struct email*)args)->content;
	char command[MAX_CONTENT];
	memset(command, 0, MAX_CONTENT);
	sprintf(command, "echo '%s' | mail -s '%s' '%s'", content, subject,  (noti_cfg.email_list)?noti_cfg.email_list:DST_EMAIL);
	system(command);
}

static void notify_by_email(char *subject, char *content){
	if (!subject || !content) return;
	struct email mail;
	mail.subject = subject;
	mail.content = content;
	sendmail(&mail);
}

void ids_engine_udp(struct udphdr *udphdr, struct timeval *pts, 
					struct sockaddr_in *src_sa, struct sockaddr_in *dst_sa)
{
	char 			payload[MAX_DATA] = { '\0' };
	unsigned short			data_len = 0;
	unsigned short			src_port = 0;
	unsigned short			dst_port = 0;
	IdsElem ids_elem;
	
	if (!udphdr || !src_sa || !dst_sa || !pts) return;

	/* info */
	src_port = ntohs(udphdr->source);
	dst_port = ntohs(udphdr->dest);
	data_len = ntohs(udphdr->len) - (unsigned short)sizeof(struct udphdr);
	if (data_len >= MAX_DATA)
		return;
		
	memcpy(payload,(unsigned char*)((unsigned char*)udphdr + sizeof(struct udphdr)),data_len);
	
	/* if not SIP */
	if (dst_port == capture_port || src_port == capture_port) {
		if (!isUdpSip((const char*)payload))
			return;
		/* create ids_elem 
		 * add to the thread-safe queue 
		 */
		ids_elem_init(&ids_elem,src_sa, dst_sa, src_port, dst_port, pts, payload);
		tsqueue_add(&ids_elem, sizeof(IdsElem));	
	}
}

void *process_ids_elem(void *data)
{
	pIdsElem idsElem_p = NULL;
	tslog_info( "[%s] Starting new thread <%p> to process ids_elem",__FUNCTION__, (void*)pthread_self()); 

#if 0	
	int fd = socket_new();
	tslog_info( "[%s] Connecting to ipds server %s:%d",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
	if (!socket_connect(fd, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port)) {
		tslog_info( "[%s] Connected to ipds server %s:%d",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
	} else { 
		tslog_info( "[%s] fd = %d - Connect to ipds server %s:%d failed, errno = %d",__FUNCTION__, fd, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port,errno);
	}
#endif 	
	char srv_addr[MAX_STR];
	memset(srv_addr, 0, MAX_STR);
	snprintf(srv_addr, MAX_STR - 1, "tcp://%s:%d", noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
	void *context = data;
	void *sender = zmq_socket (context, ZMQ_PUSH);
	zmq_connect(sender,srv_addr);
	while(true) {
		/* get the first elem from the thread-safe queue */
		idsElem_p = (pIdsElem)tsqueue_poll();

		/* process the elem - send blocked ip via fd */
		ids_engine_sip(sender, idsElem_p);

		/* free the elem */
		ids_elem_free(idsElem_p);
		if (idsElem_p)
			free(idsElem_p);
		idsElem_p = NULL;	
	}
	zmq_close(sender);
}

static void publish_blocked_ip(void *sender, const char *ip)
{
	if (!sender) return;
	char msg[MAX_STR] = { 0 };
	strcpy(msg, "src=");
	gethostname(msg + strlen(msg), 32);
	sprintf(msg + strlen(msg), ";action=block;ip=%s", ip);
	int res = 0;
	char subject[MAX_LINE] = { '\0' };
	char content[MAX_CONTENT] = { '\0' };
  	time_t now;
	int loop = 0;
sendmsg:	
	res = zmq_send (sender, msg, strlen(msg), ZMQ_DONTWAIT);
	if (res == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			/* viet - 09/12/14 - if ipds server down, abort after 3 tries */
			++loop;
			/* viet - 08/12/14 - avoid taking all CPU resources */
			/* notify us */
			sprintf(subject, "[SIP_IDS] Can not queue msg to zmq buffer anymore - verify if ipds_srv is up");
			sprintf(content, "-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
			snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "msg to queue = %s \n", msg);
			notify_by_email(subject, content);

			sleep(3);
			if (loop <= 3)
				goto sendmsg;
		}
	}
#if 0	
	int res = socket_send(*pfd, msg);
	/* fail - reconnect to server */
	if (res == -1) {
		tslog_warn( "[%s] Send to server %s:%d failed - errno = %d(%s)",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port, errno, strerror(errno));
		*pfd = socket_new();
		if (!socket_connect(*pfd, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port)) {
			tslog_info( "[%s] Connected to ipds server %s:%d",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port);
			/*resend data */
			res = socket_send(*pfd, msg);
		} else { 
			tslog_info( "[%s] Connect to ipds server %s:%d failed, errno = %d(%s)",__FUNCTION__, noti_cfg.ipds_srv_ip, noti_cfg.ipds_srv_port,errno, strerror(errno));
		}
	}
#endif	
}

void ids_engine_sip(void *sender, pIdsElem idsElem_p)
/*static void ids_engine_sip(struct udphdr *udphdr, struct timeval *pts, 
					struct sockaddr_in *src_sa, struct sockaddr_in *dst_sa)*/
{
	if (!idsElem_p) return;
	char	*payload = idsElem_p->payload;
	char	src_ip[INET_ADDRSTRLEN] = { '\0' };
	char	dst_ip[INET_ADDRSTRLEN] = { '\0' };
	unsigned short	src_port = idsElem_p->src_port;
	unsigned short	dst_port = idsElem_p->dst_port;
	struct sockaddr_in *src_sa = idsElem_p->src_sa;
	struct sockaddr_in *dst_sa = idsElem_p->dst_sa;
	pRegElem pElem = NULL;
	char fline[MAX_LINE] = { '\0' };
	int answerCode = 0;
	unsigned long interval = 0; 
	unsigned int mean = 0;
	unsigned int mean_threshold = (criteria_cfg.mean)?criteria_cfg.mean:30;
	unsigned int nbfail_threshold = (criteria_cfg.nb_fail)?criteria_cfg.nb_fail:3;
	unsigned int nbhijack_threshold = (criteria_cfg.nb_hijack)?criteria_cfg.nb_hijack:5;
	struct timeval ts = idsElem_p->tv; 
	int	newElem = 0, random = 0;
  	time_t now;
	
	/* email */
	char subject[MAX_LINE] = { '\0' };
	char content[MAX_CONTENT] = { '\0' };
	

	if (!src_sa || !dst_sa ||!payload) return;

	int data_len = strlen(payload);

	/* info */
	inet_ntop(AF_INET, &(src_sa->sin_addr), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dst_sa->sin_addr), dst_ip, INET_ADDRSTRLEN);
	
	/* sip in */
	if (dst_sa->sin_addr.s_addr == my_ip.sin_addr.s_addr &&
		dst_port == capture_port) {
		if (getFirstLine(payload, fline) < 0) return ;
		if (!isSipMsg(fline)) return;
		if (get_peer(src_ip)) {
			//printf("SIP from known peer : %s\n",src_ip);
			return;
		}
				
		time(&now);
								
		/* check From, To, UA */
		/* TODO - add regexp on From, To */	
		if (!is_good(payload, src_ip)) {
			tslog_info( "-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
			tslog_info( "Received SIP packet len=%u from <%s> port %d\n%s",data_len, src_ip, src_port,payload);
			pElem = get_reg_elem(src_ip);
			if (!pElem) {
				pElem = init_reg_elem(src_ip);
				pElem->first_ts = ts;
				add_reg_elem(pElem);
			}
			
			/* reset if necessary */
			reset_old_elem(pElem, &ts);

			pElem->nb_ua_ko++;

			if (pElem->nb_ua_ko > nbfail_threshold) {
				pElem->first_ts = ts; /* replace timestamp to calculate */
				/* add this to iptables */
				block_ip_src(src_sa->sin_addr.s_addr);
				tslog_warn("--------------> IP <%s> is blocked",src_ip);

				/* notify other sip_ids */
				publish_blocked_ip(sender, src_ip);

				if (!pElem->emailSent) {
					/* stop this bitch */
					random = rand() % blacklist.len;
					tslog_warn("--------------> sendback sip stopping this bitch <%s:%d>",src_ip,src_port);
					raw_udp_send(blacklist.blipArr[random], 6060, src_ip, src_port);
					
					/* notify us */
					sprintf(subject, "[SIP_IDS] <%s> is attacking us (Malicious From, To, UA?) -> blocked", src_ip);
					sprintf(content, "-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
					snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "Received SIP packet len=%u from <%s> port %d\n%s\n", data_len, src_ip, src_port,payload);
					snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> Send back SIP response stopping this bitch <%s:%d> - time to know what \"segmentation fault\" means baby ...\n",src_ip,src_port);
					snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> IP <%s> is blocked (payload not good: suspected From, To, UA)\n",src_ip);

					notify_by_email(subject, content);

					/* we do not authorize to send too many emails 
					 * avoiding spamming email box */ 
					pElem->emailSent = 1;
				}
			}
			return;
		}

		/* TODO - Answer instead of Request */
		/* TODO - Incomplete Session - stateful */ 

		/* anti-flooding */
		if (isREGISTER(fline) || isINVITE(fline)) {
			pElem = get_reg_elem(src_ip);
			if (!pElem) {
				newElem = 1;
				pElem = init_reg_elem(src_ip);
				pElem->first_ts = ts;
				add_reg_elem(pElem);
			}
			
			pElem->count++;
			//print_all_elem();
			
			/* do not check flooding if new */
			if(!newElem) {
				interval = (ts.tv_sec - pElem->first_ts.tv_sec) * 1000000 + (ts.tv_usec - pElem->first_ts.tv_usec);
				if (interval >= 500000) /* if interval > 3s */ {
					mean = ((pElem->count - pElem->old_count)*1000000 / interval);
					pElem->first_ts = ts; /* replace timestamp to calculate */
					pElem->old_count = pElem->count;
					if (mean > mean_threshold) {
						tslog_warn("--------> interval=%lu - Mean=%d",interval,mean);
						tslog_warn("-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
						tslog_warn("Received SIP packet len=%u from <%s> port %d\n%s",data_len, src_ip, src_port,payload);

						/* stop this bitch */
						random = rand() % blacklist.len;
						raw_udp_send(blacklist.blipArr[random], 6060, src_ip, src_port);

						block_ip_src(src_sa->sin_addr.s_addr);
						tslog_warn("--------------> IP <%s> is blocked (flooding? %d packet/%lu (micro s))",
								src_ip, pElem->count, interval); 
					
						/* notify other sip_ids */
						publish_blocked_ip(sender, src_ip);

						/* notify us */
						if (!pElem->emailSent) {
							sprintf(subject, "[SIP_IDS] <%s> is attacking us (DoS attack?) -> blocked", src_ip);
							sprintf(content, "-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
							snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "Received SIP packet len=%u from <%s> port %d\n%s\n", data_len, src_ip, src_port,payload);
							snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> Send back SIP response stopping this bitch <%s:%d> - time to know what \"segmentation fault\" means baby ...\n",src_ip,src_port);
							snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> IP <%s> is blocked (flooding? %d packet/%lu (micro s))\n",src_ip, pElem->count, interval);

							notify_by_email(subject, content);
							pElem->emailSent = 1;
						}
						
						/* remove the elem */
						reset_reg_elem(pElem,&ts);
						pElem->emailSent = 1;
					} else pElem->emailSent = 0;
				}
			}
		}
		
#if 0		
		/* Anti malicious BYE
		 * BYE message has no to-tag mandatotily came from an attacking tool
		 */
		if (isBYE(fline) && !hasToTag(payload)) {
			pElem = get_reg_elem(src_ip);
			if (!pElem) {
				pElem = init_reg_elem(src_ip);
				pElem->first_ts = ts;
				add_reg_elem(pElem);
			}
			/* reset if necessary */
			reset_old_elem(pElem, &ts);
			
			pElem->nb_hijack++;
			if (pElem->nb_hijack >=5) {
				printf("-------------------> [Thread %p] %s", pthread_self(), ctime(&now));
				printf("Received SIP packet len=%u from <%s> port %d\n%s\n",data_len, src_ip, src_port,payload);
				/* notify us */
				if (!pElem->emailSent) {
					sprintf(subject, "[SIP_IDS] <%s> is attacking us (Session end attempt?) -> blocked", src_ip,MAX_LINE -1);
					sprintf(content, "-------------------> [Thread %p] %s", pthread_self(), ctime(&now));
					snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "Received SIP packet len=%u from <%s> port %d\n%s\n", data_len, src_ip, src_port,payload);
					snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> IP <%s> is blocked (Session end attempt) - BYE without to-tag", src_ip);

					notify_by_email(subject, content);
					pElem->emailSent = 1;
				}
			}
		}
#endif		
			
#ifdef STATEFUL
		int isInvite = 0;
		int stateful_attack = 0;
		pDialog pdlg = NULL;
		char callid[MAX_LINE] = { '\0' };
		/* Anti-fraud subsequent message (ReINVITE, BYE) */
		if (stateful_enabled) {
			isInvite = isINVITE(fline);
			if ((isInvite||isBYE(fline)) && hasToTag(payload)) {
				getCallId(payload, callid);
				pdlg = get_dialog(callid);
				/* Session hijack is detected if:
				 * + The dialog does not exist
				 * + The dialog exist but the src_ip of the packet is not the same as the original ip src
				 **/
				if (!pdlg || (pdlg && !same_src(pdlg, src_ip, src_port))) {
					stateful_attack = 1;
				} 
			}
			
			/* Anti malicious BYE
			 * BYE message has no to-tag mandatotily came from an attacking tool
			 */
			if (isBYE(fline) && !hasToTag(payload)) 
				stateful_attack = 1;
			
			/* processing in case of stateful attack */
			if (stateful_attack) {
				pElem = get_reg_elem(src_ip);
				if (!pElem) {
					pElem = init_reg_elem(src_ip);
					pElem->first_ts = ts;
					add_reg_elem(pElem);
				}
				/* reset if necessary */
				reset_old_elem(pElem, &ts);

				pElem->nb_hijack++;
				tslog_warn("-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
				tslog_warn("Received SIP packet len=%u from <%s> port %d\n%s",data_len, src_ip, src_port,payload);
				if (pElem->nb_hijack >=5) {
					/* block ip */
					block_ip_src(src_sa->sin_addr.s_addr);
					tslog_warn( "--------------> IP <%s> is blocked (Session hijack attempt)",src_ip); 
					/* notify other sip_ids */
					publish_blocked_ip(sender, src_ip);
					/* notify us */
					if (!pElem->emailSent) {
						sprintf(subject, "[SIP_IDS] <%s> is attacking us (%s?) -> blocked", src_ip,  (isInvite)?"Session hijack attempt":"Session end attempt");
						sprintf(content, "-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
						snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "Received SIP packet len=%u from <%s> port %d\n%s\n", data_len, src_ip, src_port,payload);
						snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> IP <%s> is blocked (%s)", src_ip, (isInvite)?"Session hijack attempt":"Session end attempt");
						if (pdlg)
							snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), " - Dialog original src_ip:port = <%s:%d>\n",pdlg->src_ip, pdlg->src_port);
						else snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), " - Dialog <%s> does not exist\n", callid);
						snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "%s\n", (!hasToTag(payload))?"--------------> This message has no To-Tag":"");

						notify_by_email(subject, content);
						pElem->emailSent = 1;
					}
				}
			}
		}
#endif			
	}
	
	/* sip out */
	if (src_sa->sin_addr.s_addr == my_ip.sin_addr.s_addr &&
		src_port == capture_port) {
		if (getFirstLine(payload, fline) < 0) return ;
		if (!isSipMsg(fline)) return;
		if (get_peer(dst_ip)) {
			//printf("SIP to known peer : %s\n",dst_ip);
			return;
		}
		if (isAnswer(fline) && (isRegisterAnswer(payload)||isInviteAnswer(payload))) {
			getAnswerCode(fline, &answerCode);
			if ((isRegisterAnswer(payload) && answerCode > SIP_ANSWER_UNAUTHORIZED) 
				|| (isInviteAnswer(payload) 
					&& (answerCode == SIP_ANSWER_FORBIDDEN) /* forbidden */ 
					&& (answerCode == SIP_ANSWER_DLG_NOT_EXIST) /* does not exist */ 
				)){ 
				tslog_warn( "-------------------> [Thread %p] %s", (void*)pthread_self(), ctime(&now));
				tslog_warn( "SIP packet captured len=%u to <%s> port %d\n%s",data_len, dst_ip, dst_port,payload);
				pElem = get_reg_elem(dst_ip);
				
				if (pElem) {
					/* reset if necessary */
					reset_old_elem(pElem, &ts);

					switch (answerCode) {
						case SIP_ANSWER_DLG_NOT_EXIST:
							pElem->nb_hijack++; break;
						case SIP_ANSWER_FORBIDDEN:
						default:
							pElem->nb_unauth++;
							break;
					}
					if (pElem->nb_unauth >= nbfail_threshold || pElem->nb_hijack >=nbhijack_threshold ) /* only 2 times to try */ {
						pElem->first_ts = ts; /* replace timestamp to calculate */
						/* add to iptables */
						block_ip_src(dst_sa->sin_addr.s_addr);
						/* block */
						tslog_warn( "--------------> IP <%s> is blocked (nb failed auth = %d)",dst_ip, pElem->nb_unauth); 
						/* notify other sip_ids */
						publish_blocked_ip(sender, dst_ip);

						if (!pElem->emailSent) {
							/* notify us */
							sprintf(subject, "[SIP_IDS] <%s> is attacking us (too many failed attempts?) -> blocked", dst_ip);
							sprintf(content, "-------------------> %s", ctime(&now));
							snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "SIP packet captured len=%u to <%s> port %d\n%s\n", data_len, dst_ip, dst_port,payload);
							snprintf(content + strlen(content), MAX_CONTENT -1 - strlen(content), "--------------> IP <%s> is blocked (nb %s = %d)\n",
																			dst_ip, 
																			(answerCode==SIP_ANSWER_FORBIDDEN)?"failed auth":"failed session hijack",
																			(answerCode==SIP_ANSWER_FORBIDDEN)?(pElem->nb_unauth):(pElem->nb_hijack));

							notify_by_email(subject, content);
							pElem->emailSent = 1;
						}
					}
				}
			}
#ifdef STATEFUL
			/* Stateful detection */
			if (stateful_enabled) {
				if (isInviteAnswer(payload) && answerCode == SIP_ANSWER_OK) {
					getCallId(payload, callid);
					/* if fraud has been already detected on this src_ip, do not create dialog */
					pElem = get_reg_elem(dst_ip);
					if (fraudDetected(pElem)) 
						return;
					/* create a dialog */
					pdlg = NULL;
					pdlg = get_dialog(callid);
					if (!pdlg) {
						pdlg = create_dialog(callid, dst_ip, dst_port, &ts);
						add_dialog(pdlg);
					}
				}	
				/* Stateful - must delete the dialog */
				if (isByeAnswer(payload) && answerCode == SIP_ANSWER_OK) {
					getCallId(payload, callid);
					del_dialog(callid);
				}
			}
#endif			
		}
	}
}

void ids_engine_run(struct iphdr *iphdr, struct timeval *pts) 
{
	struct udphdr			*udphdr = NULL;
	struct sockaddr_in		src_sa;
	struct sockaddr_in		dst_sa;
	
	if (!iphdr) return;

	if (iphdr->protocol == IPPROTO_UDP) {
		udphdr = (struct udphdr*)((unsigned char*)iphdr + sizeof(struct iphdr));
		/* src_ip */
		src_sa.sin_family = AF_INET; /* ipv4 */
		src_sa.sin_addr.s_addr = iphdr->saddr;

		/* dst ip */
		dst_sa.sin_family = AF_INET; /* ipv4 */
		dst_sa.sin_addr.s_addr = iphdr->daddr;
		
		/* udp */
		ids_engine_udp(udphdr,pts, &src_sa, &dst_sa);
	}
}
#ifdef __cplusplus
}
#endif

