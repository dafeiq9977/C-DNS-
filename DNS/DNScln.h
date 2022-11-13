#ifndef DNSCLN_H_
#define DNSCLN_H_
int parseOrder(dns_query *question, int argc, char *argv[]);
unsigned short isType(const char *str, const int len);
unsigned char *nameSwitch(char *name, int len);
void initQueryHead(dns_header *head);
int TCP_connection(int s, struct sockaddr_in *server_addr, unsigned short port, char *det);
unsigned int initDNSQueryPacket(char *buf, dns_header *head, dns_query *question);
void parseResponse(char *buf, unsigned int len);
unsigned int sendQuery(int s, char *buf, unsigned int len);
unsigned int downRR(char *buf, char *cur, dns_rr *rRecord);
unsigned int downQuery(char *q, dns_query *query);
char * reverseNameSwitch(char *name);
unsigned int getPTRName(char *name);
#endif
