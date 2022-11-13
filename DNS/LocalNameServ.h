#ifndef _LOCALNAMESERV_H_
#define _LOCALNAMESERV_H_
#include "DNS.h"

#define HEADER_LEN 12

int initServer();
unsigned int generateResponse (char *, dns_header, dns_query, dns_rr, int);
unsigned int generateQuery (char *, dns_query);
void generateRespHead (char *, dns_header *, int, int, int);
void generateQueryHead (dns_header *);
char *getQuery (char *, dns_query *, int, int);
int checkCache(char *, dns_query *, dns_rr *);
char *parseDomainName (char *, int *);
unsigned char *formatDomainName (char *, int);
unsigned short parseType(char *);
unsigned short parseClass(char *);
char **splitRR(char *);


int initServer()
{
	int sock_fd;
	struct sockaddr_in localServAddr;
	if ((sock_fd=socket(PF_INET, SOCK_STREAM, 0))<0)
	{
		printf("socket() failed.\n");
		exit(1);	
	}

	memset(&localServAddr, 0, sizeof(localServAddr));
	localServAddr.sin_family = AF_INET;
	localServAddr.sin_addr.s_addr = inet_addr("127.0.0.2");
	localServAddr.sin_port = htons(53);

	if ((bind(sock_fd, (struct sockaddr *)&localServAddr, sizeof(localServAddr))) < 0)
	{
		printf("bind() failed.\n");
		exit(1);
	}
	
	return sock_fd;
}


// generate resp to the client
unsigned int generateResponse (char *buf, dns_header head, dns_query query, dns_rr rr, int haveAns)
{
	unsigned int offset=0;
	memcpy(buf+2, &head, 12);
	offset += 12;
	unsigned int queryLen = strlen(query.name)+1;
	memcpy(buf+2+offset, query.name, queryLen);
	offset += queryLen;
	memcpy(buf+2+offset, &(query.qtype), 4);
	offset += 4;
	if (haveAns==1)
	{
		char namePtr1 = (char)0xc0;
		memcpy(buf+2+offset, &namePtr1, 1);
		offset +=1;
		char namePtr2 = (char)0x0e;
		memcpy(buf+2+offset, &namePtr2, 1);
		offset +=1;
		memcpy(buf+2+offset, &(rr.type), 10);
		offset += 10;
		int rdata_len = strlen(rr.rdata);
		memcpy(buf+2+offset, rr.rdata, rdata_len);
		offset += rdata_len;
	}
	unsigned short resp_len = strlen(buf+2);
	memcpy(buf, &resp_len, 2);

	return (unsigned int)strlen(buf);
}

// generate query to other nameserver
unsigned int generateQuery (char *buf, dns_query query)
{
	dns_header header;
	memset(&header, 0, sizeof(dns_header));
	initHead (&header);
	generateQueryHead(&header);
	unsigned int offset=0;
	memcpy(buf, &header, 12);
	offset += 12;
	unsigned int queryLen = strlen(query.name)+1;
	memcpy(buf+offset, query.name, queryLen);
	offset += queryLen;
	memcpy(buf+offset, &(query.qtype), 4);

	return (unsigned int)strlen(buf);
}

// generate the resp header to client
void generateRespHead (char *clntMsg, dns_header *head, int ans, int addition, int authoritative)
{
	char *id = "00";
	memcpy(id, clntMsg+2, 2);
	head->id = (short)strtol(id, NULL, 16);
	unsigned short flag = 0;
	flag = ((flag & QR) & NAME_TO_ADDR) & SUCCESS;
	if (authoritative==1)
		flag = flag & AA;

	head->tag = flag;
	head->queryNum = 1;
	head->answerNum = ans;
	head->authorNum = 0;
	if (addition==1)
		head->addNum = 1;
	else
		head->addNum = 0;
}

void generateQueryHead (dns_header *head)
{
	char *id = "01";
	head->id = (short)strtol(id, NULL, 16);
	unsigned short flag = 0;
	head->tag = flag;
	head->queryNum = 1;
	head->answerNum = 0;
	head->authorNum = 0;
	head->addNum = 0;
}

// get query struct from client's msg
char *getQuery (char *msg, dns_query *query, int recvLen, int headerLen)
{
	int size = recvLen;
	unsigned char *temp=(unsigned char *)malloc(size);
	memcpy(temp, msg+headerLen, size);
	int offset=0;
	char *nameDotStr = parseDomainName(temp, &offset);
	unsigned char *name = (unsigned char *)malloc(offset);
	memcpy(name, temp, offset);
	unsigned char *type = (unsigned char *)malloc(3);
	memcpy(type, temp+offset+1, 3);
	unsigned char *clas = (unsigned char *)malloc(3);
	memcpy(clas, temp+offset+3, 3);

	query->name = name;
	query->qtype = *(type+1);
	query->qclass = *(clas+1);

	free(name); free(type); free(clas);
	return nameDotStr;
}

// check the query in local cache. If contains, generate the RR
int checkCache(char *nameDotStr, dns_query *query, dns_rr *rr)
{
	FILE *cache;
	int flag=-1;

	if ((cache=fopen("cache.txt", "r"))==NULL)
	{
		printf("open cache file failed.\n");
		return flag;
	}
	char records[60];
	while (fgets(records, 60, cache)!=NULL)
	{
		char **content = splitRR(records);
		if (strcmp(content[0], nameDotStr))
		{
			if (parseType(content[1])==query->qtype)
			{
				printf("passpass\n");
				//
				rr->name = formatDomainName(nameDotStr, strlen(nameDotStr));
				printf("formatPP\n");
				rr->type = htons(parseType(content[1]));
				rr->rclass = htons(parseClass(content[2]));
				rr->ttl = htonl(atoi(content[3]));
				//rr->data_len = htons(strlen(content[4]));
				if (rr->type = htons(A_TYPE))
				{
					in_addr_t addr = inet_addr(content[4]);
					rr->data_len = htons(4);
					sprintf(rr->rdata, "%d", addr);
				}
				else
				{
					unsigned char *data = formatDomainName(content[4], strlen(content[4]));
					rr->data_len = htons(strlen(data));
					rr->rdata = data;
				}
				flag = 0;
			}
		}
		else continue;
	}
	fclose(cache);
	return flag;
}

// char *sendToRoot(char *buf)
// {
// 	struct 
// }

// msg: string start with the domain name in dns_query format
// len: the original length of domain name in msg
// return domain name with '.'
char *parseDomainName (char *msg, int *len)
{
	char *str = (char *)malloc(60);
	memset(str, 0, 60);
	int offset = 0;
	while (*msg != '\0')
	{
		int num = *msg;
		memcpy(str+offset, msg+1, num);
		offset += num;
		*(str+offset) = '.';
		offset += 1;
		msg = msg + num + 1;
	}
	*len = offset;
	
	char *rslt = (char *)malloc(strlen(str));
	strncpy(rslt, str, strlen(str)-1);
	*(rslt+(strlen(str)-1)) = '\0';
	
	free(str);
	return rslt;
}

// format the '.' split domain name
// into dns msg type
unsigned char *formatDomainName (char *name, int len)
{
	printf("%s %d\n",name, len);
	printf("11111\n");
	printf("11111\n");
	unsigned char *buf = (unsigned char *)malloc(len+2);
	// char *buf = (char *)malloc(len+2);
	printf("11111\n");
	// if(buf == NULL){
	// 	printf("Fatal Error: No enough memory!\n");
	// 	return NULL;
	// }
	printf("11111\n");
	memset(buf,0,len+2);
	int i = 0;
	char count = 0,cur = 0;
	for(i=0; i<=len; i++){
		if(name[i] == '.' || i == len){
			buf[cur] = count;
			count+=1;
			cur += count;
			count = 0;
		}else{
			count++;
			buf[cur + count] = name[i];
		}
	}
	buf[len+1] = '\0';
	printf("%s\n",buf);
	return buf;
}

// parse a type string into unsigned short
unsigned short parseType(char *type)
{
	if (strcmp(type, "A")==0)
		return A_TYPE;
	else if (strcmp(type, "NS")==0)
		return NS_TYPE;
	else if (strcmp(type, "MX")==0)
		return MX_TYPE;
	else if (strcmp(type, "CNAME")==0)
		return CNAME_TYPE;
	else if (strcmp(type, "PTR")==0)
		return PTR_TYPE;
	else
		return 0;
}

// parse a class string into unsigned short
unsigned short parseClass(char *clas)
{
	if (strcmp(clas, "IN")==0)
		return 0x0001;
	else return 0;
}

// split each part of RRs in db
char **splitRR(char *rr)
{
	char **rslt;
	int count = 0;
	char *delim = " ";
	rslt = (char **)malloc(5*sizeof(char *));
	*(rslt+count) = strtok(rr, delim);
	while (rslt[count]!=NULL)
	{
		count++;
		*(rslt+count) = strtok(NULL, delim);
	}
	return rslt;
}


#endif /*_LOCALNAMESERV_H_*/
