#ifndef __SIP_FCT__
#define	__SIP_FCT__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define	MAX_LINE	128	
#define MAX_FIELD_NAME	32

/* 2XX */
#define SIP_ANSWER_OK				200

/* 4XX */
#define SIP_ANSWER_UNAUTHORIZED		401
#define	SIP_ANSWER_FORBIDDEN		403
#define SIP_ANSWER_DLG_NOT_EXIST	481
int getFirstLine(const char *payload, char *fline);
int getCSeq(const char *payload, char *cseq);
int getFrom(const char *payload, char *from);
int getTo(const char *payload, char *to);
int getCallId(const char *payload, char *callid);
int hasToTag(const char *payload);
int getFirstVia(const char *payload, char *fvia);
int isRegisterAnswer(const char *payload);
int isByeAnswer(const char *payload);
int isInviteAnswer(const char *payload);
int isAnswer(const char *fline);
int isSipMsg(const char *fline);
int isUdpSip(const char *payload);
int isREGISTER(const char *fline);
int isINVITE(const char *fline);
int isBYE(const char *fline);
int getUA(const char *payload, char *ua);
int getAnswerCode(const char *fline, int *code);
int is_good(const char *payload, const char *src_ip);

#endif
