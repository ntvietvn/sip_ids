#ifdef __cplusplus
extern "C" {
#endif	
#include "sip_fct.h"

int getFirstLine(const char *payload, char *fline) {
	if (!payload || !fline) return -1;
	char *str = strchr(payload, '\n');
	if (str)
		memcpy(fline, payload, str-payload);
	return 0;	
}

static int getField(const char *payload, char *field, char *fieldName) {
	if (!payload || !field || !fieldName) return -1;
	char *str = strstr(payload, fieldName);
	if (!str)
		return -1;
	char *str2 = strchr(str, '\r');
	if (!str2)
		str2 = strchr(str, '\n');	
	if (!str2)	
		return -1;
	int len = strlen(fieldName);	
	memcpy(field, str + len, str2-str-len);		
	return 0;
}

int getCSeq(const char *payload, char *cseq) {
	if (!payload || !cseq) return -1;
	char *str = strstr(payload, "CSeq:");
	if (!str)
		return -1;
	char *str2 = strchr(str, '\n');
	if (!str2)
		return -1;
	memcpy(cseq, str, str2-str);		
	return 0;
}

int getFrom(const char *payload, char *from) {
	if (!payload || !from) return -1;
	char *str = strstr(payload, "From:");
	if (!str)
		return -1;
	char *str2 = strchr(str, '\n');
	if (!str2)
		return -1;
	memcpy(from, str, str2-str);		
	return 0;
}

int getTo(const char *payload, char *to) {
	char toName[MAX_FIELD_NAME] = { 0 };
	strncpy(toName, "To:", MAX_FIELD_NAME -1);
	return getField(payload, to, toName);
}

int getCallId(const char *payload, char *callid) {
	char name[MAX_FIELD_NAME] = { 0 };
	strncpy(name, "Call-ID: ", MAX_FIELD_NAME -1);
	return getField(payload, callid, name);
}


int hasToTag(const char*payload) {
	char to[MAX_LINE] = { 0 };
	getTo(payload, to);
	char *str = NULL;
	if (to[0]) {
		str = strstr(to, "tag=");
	}
	return (str)?1:0;
}

static int isAnswerOfMethod(const char *payload, const char* method){
	char cseq[MAX_LINE] = { '\0' };
	int res = getCSeq(payload, cseq);
	if (res < 0) return 0;
	if (!method) return 0;
	char *substr = strstr(cseq, method);
	return (substr)?1:0;
}

/* re-entrant */
int isInviteAnswer(const char *payload) {
	char methodName[MAX_FIELD_NAME] = { 0 };
	strncpy(methodName, "INVITE", MAX_FIELD_NAME-1);
	return isAnswerOfMethod(payload, methodName);
}

int isByeAnswer(const char *payload) {
	char methodName[MAX_FIELD_NAME] = { 0 };
	strncpy(methodName, "BYE", MAX_FIELD_NAME-1);
	return isAnswerOfMethod(payload, methodName);
}

int isRegisterAnswer(const char *payload) {
	char methodName[MAX_FIELD_NAME] = { 0 };
	strncpy(methodName, "REGISTER", MAX_FIELD_NAME-1);
	return isAnswerOfMethod(payload, methodName);
}

int isAnswer(const char *fline) {
	if (!fline) return 0;
	const char *sip_cst = "SIP/2.0";
	if (strlen(fline) <= strlen(sip_cst))
		return 0;
	return !memcmp(fline, sip_cst, strlen(sip_cst));	
}

int isSipMsg(const char *fline) {
	if (!fline) return 0;
	const char *sip_cst = "SIP/2.0";
	if (strlen(fline) <= strlen(sip_cst))
		return 0;
	return (strstr(fline, sip_cst))?1:0;
}

int isUdpSip(const char *payload) {
	if (!payload) return 0;
	const char *sip_cst = "SIP/2.0";
	const char *from = "From:";
	const char *to = "To:";
	char *substr = strstr(payload, sip_cst);
	if (!substr) return 0;
	if (strstr(substr, from) && strstr(substr, to))
		return 1;
	else return 0;	
}

int isREGISTER(const char *fline) {
	return (strstr(fline, "REGISTER"))?1:0;
}

int isINVITE(const char *fline) {
	return (strstr(fline, "INVITE"))?1:0;
}

int isBYE(const char *fline) {
	return (strstr(fline, "BYE"))?1:0;
}

int getFirstVia(const char *payload, char *fvia) {
	char *substr = strstr(payload, "Via:");
	if (!substr)
		return -1;
	char *str2 = strchr(substr, '\n');
	if (!str2)
		return -1;
	memcpy(fvia, substr, str2 - substr); 
	return 0;
}

int getUA(const char *payload, char *ua) {
	char *substr = strstr(payload, "User-Agent:");
	if (!substr)
		return -1;
	char *str2 = strchr(substr, '\n');
	if (!str2)
		return -1;
	memcpy(ua, substr, str2 - substr); 
	return 0;
}

int getAnswerCode(const char *fline, int *code) {
	sscanf(fline, "SIP/2.0 %d", code);
	return 0;
}

static int good_user_agent(const char *useragent) {
	if (!useragent) return 0;
	if (strstr(useragent, "scan")
		|| strstr(useragent, "sipp")
		|| strstr(useragent, "sundayddr")
		|| strstr(useragent, "sipcli")
		|| strstr(useragent, "sipsak")
		|| strstr(useragent, "sip-scan")
		|| strstr(useragent, "iWar")
		|| strstr(useragent, "sipvicious"))
		return 0;
	return 1;
}

static int good_from(const char *from) {
	if (!from) return 0;
	if (strstr(from, "scan")
		|| strstr(from, "sipp")
		|| strstr(from, "sundayddr")
		|| strstr(from, "sipcli")
		|| strstr(from, "sipsak")
		|| strstr(from, "sip-scan")
		|| strstr(from, "iWar")
		|| strstr(from, "sipvicious"))
		return 0;
	return 1;
}
/*
static int good_via(const char *via, const char *src_ip) {
	if (!via) return 0;
	return (strstr(via, src_ip))?1:0;
}
*/
int is_good(const char *payload, const char *src_ip)
{
	char from[MAX_LINE] = { '\0' };
	char ua[MAX_LINE] = { '\0' };
	//char fvia[MAX_LINE] = { '\0' };
	//getFirstVia(payload, fvia);
	//if (!good_via(fvia, src_ip)) return 0;
	getUA(payload, ua);
	if (!good_user_agent(ua)) return 0;
	getFrom(payload, from);
	if (!good_from(from)) return 0;
	return 1;
}
#ifdef __cplusplus
}
#endif
