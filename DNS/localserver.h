#ifndef QPRLOCAL_SERVER_H_
#define QPRLOCAL_SERVER_H_
unsigned int questResult(char *rec, int recLen, char *res);
unsigned int searchCache(char *name, char *r, dns_header *head);
unsigned int upRR(char *r, dns_rr *rRecord);
unsigned short getType(char *ch);
unsigned int UDPConnection(in_addr_t addr, char *content, int contentLen, char *result);
unsigned int downHead(char *q, dns_header *head);
unsigned int downQuery(char *q, dns_query *query);
int cmpDomainName(char *name, char *col, long nowsec);
unsigned int upQuery(char *r, const dns_query *query);
int blocklen(char *cur);
char * reverseNameSwitch(char *name);
char * nameSwitch(char *name);
unsigned int downRR(char *buf, char *cur, dns_rr *rRecord);
void addToCache(char *res);
#endif