/*
 * this file includes some constants in DNS lab
 * and define related structures
 */

#ifndef DNS_H_
#define DNS_H_
#define DNSMAXLEN 526
#define QR 32768
#define NAME_TO_ADDR 0
#define ADDR_TO_NAME 2048
#define SERV_STAT 4096
#define AA 1024
#define TC 512
#define RD 256
#define RA 128
#define SUCCESS 0
#define FORMAT_ERR 1
#define SERV_ERR 2
#define NOT_EXIST 3
#define FORMAT_NOT_SUPPORT 4
#define POLICY 5
#define A_TYPE 1
#define NS_TYPE 2
#define CNAME_TYPE 5
#define MX_TYPE 15
#define PTR_TYPE 12
#define IN 1 

//define DNS head structure 
struct DNS_Header{
	unsigned short id;
	unsigned short tag;
	unsigned short queryNum;
	unsigned short answerNum;
	unsigned short authorNum;
	unsigned short addNum;
};

typedef struct DNS_Header dns_header;

//define DNS query structure
struct DNS_Query{
	unsigned char* name;
	unsigned short qtype;
	unsigned short qclass;
};
typedef struct DNS_Query dns_query;

// define DNS resource record structure
struct DNS_RR{
	unsigned char *name;
	unsigned short type;
	unsigned short rclass;
	unsigned int ttl;
	unsigned short data_len;
	unsigned char *rdata;
};

typedef struct DNS_RR dns_rr;

// three functions below are interfaces to init structures
void initHead(dns_header *head){
	head->id=0;
	head->tag=0;
	head->queryNum=0;
	head->answerNum=0;
	head->authorNum=0;
	head->addNum=0;
}
// 
void initQuery(dns_query *query){
	if(query->name!=NULL){
		free(query->name);
		query->name=NULL;
	}
	query->qtype=0;
	query->qclass=0;
}
void initRR(dns_rr *rr){
	if(rr->name!=NULL){
		free(rr->name);
		rr->name=NULL;
	}
	if(rr->rdata!=NULL){
		free(rr->rdata);
		rr->rdata=NULL;
	}
	rr->type=0;
	rr->rclass=0;
	rr->ttl=0;
	rr->data_len=0;
}

#endif
