#ifndef SERVER_H_
#define SERVER_H_
#include"tree.h"
typedef struct nextserver 
{
    char *domain;
    char *ser_name;
    char *IP_addr;
}nextserver;

int blocklen(char *cur);
unsigned int upRR(char *r, dns_rr *rRecord);
int isMatch(char *qName, char *serName);
unsigned int addAuthor(char *qName, nextserver *servers, int row, dns_rr *rRecord, tree *dictree, int offset, char *r);
void initServerInfo(nextserver *servers, char *col);
int isBigEndien();
unsigned int downHead(char *q, dns_header *head);
unsigned int downQuery(char *q, dns_query *query);
unsigned int upQuery(char *r, const dns_query *query);
unsigned int compare(const dns_query *query, const char *col);
unsigned int cmpDomainName(const char *name, const char *col);
unsigned int cmpTypeClass(const unsigned short type, const char *col);
unsigned int getAnswerRR(char *col, dns_rr *rRecord, dns_query *query, tree *dictree, int offset);
char * reverseNameSwitch(char *name);
char * nameSwitch(char *name);
int htoni(int a);
#endif