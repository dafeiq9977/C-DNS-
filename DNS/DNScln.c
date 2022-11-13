/*
 * this file includes DNS client code
 * written by Qu Peiran on 2020.6.2
 * using blank line to seperate each section
 */

#include"dnshead.h"
#include"DNScln.h" 
#include<sys/time.h>


int main(int argc, char *argv[]){
	// two timeval structure used to calculate time difference
	struct timeval before,after;
	
	// check number of arguments
	if(argc<2){ printf("too few arguments\n");return 0;}
	else if(argc>3){ printf("too many arguments\n");return 0;}
	else{ 
		// convert user inputs to dns_query structure
		dns_query *question = (dns_query *)malloc(sizeof(dns_query)); initQuery(question); 
		if(parseOrder(question, argc, argv) == -1){
			initQuery(question); free(question);
			exit(-1);
		};
		// write head to request packet
		dns_header *head = (dns_header *)malloc(sizeof(dns_header)); initHead(head);	
		initQueryHead(head);
		
		// using dns_query structure and dns_header structure to get request packet
		char *buf = (char *)malloc(DNSMAXLEN * sizeof(char));
		unsigned int qLength = initDNSQueryPacket(buf, head, question);
		
		//add request packet length at the beginning
		unsigned int h = htons(qLength);
		memcpy(buf, &h, 2);
		qLength += 2;
		
		// release memory
		initHead(head);free(head); initQuery(question); free(question);
		
		/*
	 	*	establish TCP connection
		*/
		struct sockaddr_in server_addr;
		int socketNum;
		socketNum = socket(AF_INET, SOCK_STREAM, 0);
		if(socketNum<0){printf("socket error!\nabort!\n"); perror("Reason: "); exit(-1);}
		if(TCP_connection(socketNum, &server_addr, 53, "127.0.0.2")==-1){
			printf("Connection failed!\nabort!\n"); perror("Reason:");
			exit(-1);
		}
		
		// calculate time difference
		gettimeofday(&before,NULL);
		unsigned int size = sendQuery(socketNum, buf, qLength);
		gettimeofday(&after,NULL);
		
		// parse response packet and print it on the screen
		parseResponse(buf, size);
		printf("Results come back after %ld us\n",(after.tv_sec-before.tv_sec)*1000000+(after.tv_usec-before.tv_usec));
		free(buf);
		close(socketNum);
	}
}
 
// this function establish TCP connection to local server
int TCP_connection(int s, struct sockaddr_in *server_addr, unsigned short port, char *det){
	bzero(server_addr, sizeof(server_addr));
	server_addr->sin_family = AF_INET;
	server_addr->sin_addr.s_addr = inet_addr("127.0.0.2");
	server_addr->sin_port = htons(port);
	inet_pton(AF_INET, det, &(server_addr->sin_addr));
	int c = connect(s, (struct sockaddr *)server_addr, sizeof(struct sockaddr));
	return c;
}

// this function parses response packet and display the result on the screen
void parseResponse(char *buf, unsigned int len){
	
	char *cur = buf+2;
	dns_header *resHeader = (dns_header *)malloc(sizeof(dns_header)); initHead(resHeader);
	memcpy(resHeader, cur, sizeof(dns_header));
	cur += sizeof(dns_header);
	unsigned short mask = 15;
	unsigned short rcode = htons(resHeader->tag) & mask;
	
	// print messages in DNS response packet according to the rcode value
	if(rcode==FORMAT_ERR){
		printf("Query Format Error!\n");
	}else if(rcode==SERV_ERR){
		printf("Server Error!\n");
	}else if(rcode==NOT_EXIST){
		printf("Domain name not exist!\n");
	}else if(rcode==FORMAT_NOT_SUPPORT){
		printf("Format not support\n");
	}else if(rcode==POLICY){
		printf("Can not acquire IP due to the political reason!\n");
	}else if(rcode==SUCCESS){
		unsigned short aa = htons(resHeader->tag) & AA;
		if(aa){
			printf("Received authoritative reponse:\n");
		}else{
			printf("Received nonauthoritative response:\n");
		}
		
		// get the number of four sections
		unsigned short num[4];
		num[0] = htons(resHeader->queryNum); num[1] = htons(resHeader->answerNum);
		num[2] = htons(resHeader->authorNum); num[3] = htons(resHeader->addNum);
		dns_rr *rRecord=(dns_rr *)malloc(sizeof(dns_rr));
		dns_query *question=(dns_query *)malloc(sizeof(dns_query));
		cur += downQuery(cur, question);
		int i = 1;
		while(i<4){
			while(num[i]>0){
				// put one resource record to dns_rr structure
				cur += downRR(buf, cur, rRecord);
				printf("[RESOURCERECORD]\nName		:	%s\n",		// print domain name
					reverseNameSwitch(rRecord->name));
				printf("Type:		:");
				switch(htons(rRecord->type)){					// print query type
					case A_TYPE: printf("	A\n"); break;
					case MX_TYPE: printf("	MX\n"); break;
					case CNAME_TYPE: printf("	CNAME\n"); break;
					case PTR_TYPE: printf("	PTR\n");
				}
				printf("class		:	IN\n");		// print class type
				printf("TTL		:	%u sec\n",htonl(rRecord->ttl));	// print TTL
				printf("Data_Len	:	%hu bytes\n",htons(rRecord->data_len));	// print answer length
				if(rRecord->type==htons(MX_TYPE)){		// process MX type alone
					unsigned short preference=0;
					memcpy(&preference, rRecord->rdata, sizeof(short));
					printf("preference	:	%hu\n", htons(preference));		// print preference
					printf("IP|DAMAIN	:	%s\n", reverseNameSwitch(rRecord->rdata+sizeof(short)));
				}else{
					if(rRecord->type==htons(A_TYPE)){		// process A type alone
						int i=0;
						printf("IP|DAMIN	:	");
						for(;i<3;i++){
							printf("%d.",rRecord->rdata[i]);
						}
						printf("%d\n",rRecord->rdata[3]);
					}else{
						printf("IP|DOMAIN	:	%s\n",reverseNameSwitch(rRecord->rdata));
					}
				}
				printf("=====================================================\n");
				initRR(rRecord); initQuery(question);
				num[i]--;
			}
			i++;
		}
	 	free(rRecord); free(question);
	}else{ printf("Unknow type!\n");free(resHeader);return;}
	initHead(resHeader);free(resHeader);
}

// this function copies resource record in response packet to dns_rr structure
unsigned int downRR(char *buf, char *cur, dns_rr *rRecord){
	unsigned int offset = 0;
	int len = 0;
	char pointer=0xc0;
	if(cur[0]==pointer){
		char *tmp=cur;
		cur = buf+cur[1]+2;
		len = strlen(cur)+1;
		rRecord->name = (char *)malloc(len*sizeof(char));
		memcpy(rRecord->name, cur, len);
		cur = tmp + 2; offset+=2;
	}else{
		len =strlen(cur)+1;
		rRecord->name = (char *)malloc(len*sizeof(char));
		memcpy(rRecord->name, cur, len);
		cur+=len; offset+=len;
	}
	memcpy(&(rRecord->type), cur, 3*sizeof(short)+sizeof(int));
	cur+=3*sizeof(short)+sizeof(int); offset+=3*sizeof(short)+sizeof(int);
	unsigned short data_len = htons(rRecord->data_len);
	rRecord->rdata = (char *)malloc(data_len*sizeof(char));
	memcpy(rRecord->rdata, cur, data_len);
	offset+=data_len;
	return offset;
}

// this function generates DNS query packet
unsigned int initDNSQueryPacket(char *buf, dns_header *head, dns_query	*question){
	unsigned short type = question->qtype;
	head->id = htons(head->id);
	head->tag = htons(head->tag);
	head->queryNum = htons(head->queryNum);
	question->qtype = htons(question->qtype);
	question->qclass = htons(question->qclass);
	buf += 2; 
	memcpy(buf, head, sizeof(dns_header));
	buf += sizeof(dns_header);
	unsigned int offset=sizeof(dns_header);
	unsigned int questionLen = strlen(question->name)+1;
	if(type==PTR_TYPE){
		char queryName[questionLen+13]; memcpy(queryName, question->name, questionLen);
		// if the query type is PTR, add suffix in-addr.arpa
		questionLen=getPTRName(queryName);
		char *name=nameSwitch(queryName, strlen(queryName));
		memcpy(buf, name, questionLen);
		offset+=questionLen;
	}else{
		memcpy(buf, question->name, questionLen);
		offset += questionLen;
	}
	memcpy(buf+questionLen, &(question->qtype), 4);
	offset += 4;
	return offset;
}

// this function adds suffix in-addr.arpa behind query name
unsigned int getPTRName(char *name){
	reverseNameSwitch(name);
	int len=strlen(name);
	int start=0, end=len-1;
	char tmp=0;
	while(end>start){
		tmp=name[start];
		name[start]=name[end];
		name[end]=tmp;
		start++; end--;
	}
	strcat(name, ".in-addr.arpa");
	return len+2+13;
}

// this function send request packet and wait for response from localserver
unsigned int sendQuery(int s, char *buf, unsigned int len){
	send(s, buf, len, 0);
	memset(buf, 0, len);
	unsigned int size = recv(s, buf, DNSMAXLEN,0);
	return size;
}

// this function copy query section in response packet to dns_query structure
unsigned int downQuery(char *q, dns_query *query){
	int len = strlen(q)+1;
	query->name = (char *)malloc(len*sizeof(char));
	memcpy(query->name, q, len);
	q += len;
	memcpy(&(query->qtype), q, 2*sizeof(short));
	return len + 2*sizeof(short);
}

// this function returns query type if type is legal. otherwise report error
unsigned short isType(const char *str, const int len){
	if(len>8||len<4) return 254;
	int i;
	char copy[len+1];
	strcpy(copy,str);
	for(i=0; i<len-3; i++){copy[i+3]=toupper(copy[i+3]);}
	if(!strcmp(copy, "-q=A")) {return A_TYPE;}
	else if(!strcmp(copy,"-q=MX")) {return MX_TYPE;}
	else if(!strcmp(copy, "-q=PTR")) {return PTR_TYPE;}
	else if(!strcmp(copy, "-q=CNAME")) {return CNAME_TYPE;}
	return 254;
}

// this function switch normal string to DNS format
unsigned char * nameSwitch(char * name, int len){
	unsigned char *buf = (char *)malloc((len+2)*sizeof(unsigned char));
	if(buf == NULL){
		printf("Fatal Error: No enough memory!\n");
		return NULL;
	}
	memset(buf,0,len);
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
	return buf;
}

// this function switch DNS string to normal format
char * reverseNameSwitch(char *name){
	if(strlen(name)<2) {printf("worng format!\n");return name;}
	char count=name[0];
	int i=1;
	while(name[i]!=0){
		if(count==0){
			count=name[i];
			name[i-1]='.';
			i++;
		}else{
			name[i-1]=name[i];
			count--;
			i++;
		}
	}
	name[i-1]='\0';
	return name;
}

// this function get query type and domain name from user input
int parseOrder(dns_query *question, int argc, char *argv[]){
	question->qclass = 0;
	if(argc == 2){
		question->name = nameSwitch(argv[1], strlen(argv[1]));
		question->qtype = 1;
		question->qclass = 1;
	}else{
		unsigned short type = isType(argv[1],strlen(argv[1]));
		if(type!=254){
			question->name = nameSwitch(argv[2],strlen(argv[2]));
			question->qtype = type;
			question->qclass = 1;
		}else{
			type = isType(argv[2],strlen(argv[2]));
			if(type==254){
				printf("wrong format!\n");
				return -1;
			}
			question->name = nameSwitch(argv[1],strlen(argv[1]));
			question->qtype = type;
			question->qclass = 1;
		}
	}
	return 0;
}

// this function initialize head section
void initQueryHead(dns_header *head){
	head->id = 1;
	head->queryNum = 1;
}




