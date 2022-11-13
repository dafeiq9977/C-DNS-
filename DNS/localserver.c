#include "dnshead.h"
#include "QPRlocalserver.h"
#include <sys/time.h>
#define PORT 53
const char *nextserver = "127.0.0.3"; 
int main(int argc, char *argv[]){
	int ss,sc;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	ss = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.2");
	server_addr.sin_port = htons(PORT);
	int err = bind(ss, (struct sockaddr *)&server_addr, sizeof(server_addr));
	err = listen(ss,1);
	char rec[DNSMAXLEN]; memset(rec, 0, DNSMAXLEN);
	char res[DNSMAXLEN]; memset(res, 0, DNSMAXLEN);
	while(1){
		socklen_t addrlen = sizeof(struct sockaddr);
		sc = accept(ss, (struct sockaddr *)&client_addr, &addrlen);
		unsigned int size = recv(sc, rec, DNSMAXLEN,0);
		int resLen = questResult(rec, size, res);
		send(sc, res, resLen, 0);
		memset(rec, 0, DNSMAXLEN);
		memset(res, 0, DNSMAXLEN);
		close(sc);
	}
	close(ss); 
} 

unsigned int questResult(char *rec, int recLen, char *res){
	unsigned int resLen=0;
	dns_header *head = (dns_header *)malloc(sizeof(dns_header)); initHead(head);
	dns_query *query = (dns_query *)malloc(sizeof(dns_query));
	char *q=rec; char *r=res;
	q += 2+sizeof(dns_header);
	q += downQuery(q, query);
	r+=2+sizeof(dns_header); 
	r+=upQuery(r, query);
	resLen += r-res;
	nameSwitch(query->name);
	unsigned short tmp=0;
 
	if((tmp=searchCache(query->name, r, head))!=0){
		head->authorNum=0; head->addNum=0;
		head->tag = htons(0 | QR | SUCCESS);
		head->id = htons(1);
		head->queryNum = htons(1);
		unsigned short length = htons(tmp + resLen-2);
		memcpy(res, &length, 2);
		memcpy(res+2, head, sizeof(dns_header));
		initHead(head); initQuery(query);
		free(head); free(query);
		return resLen+tmp;
	}
	unsigned int UDPLen = UDPConnection(inet_addr(nextserver), rec+2, recLen-2, res);
	while(1){
		memcpy(head, res, sizeof(dns_header));
		if(head->authorNum!=0){
			char *p=res;
			p+=sizeof(dns_header);
			p+=strlen(p)+1;
			p+=2*sizeof(short);
			p+=strlen(p)+1;
			p+=3*sizeof(short)+sizeof(int);
			p+=strlen(p)+1;
			p+=2;
			p+=3*sizeof(short)+sizeof(int);
			in_addr_t addr; memset(&addr, 0, sizeof(addr));
			memcpy(&addr, p, sizeof(addr));
			memset(res, 0, UDPLen);
			UDPLen = UDPConnection(addr, rec+2, recLen-2, res);
		}else{
			addToCache(res);
			char tmp[DNSMAXLEN]; memset(tmp, 0, DNSMAXLEN);
			memcpy(tmp, res, UDPLen);
			unsigned short length = htons(UDPLen);
			memcpy(res, &length, 2);
			memcpy(res+2, tmp, UDPLen);
			return UDPLen+2;
		}
	}
}

void addToCache(char *res){
	char *hook = res;
	unsigned short rrNum=0;
	dns_header *head = (dns_header *)malloc(sizeof(dns_header));
	dns_rr *rRecord = (dns_rr *)malloc(sizeof(dns_rr));
	FILE *fp = fopen("cache.txt", "a");
	memcpy(head, hook, sizeof(dns_header));	hook+=sizeof(dns_header);
	rrNum=htons(head->answerNum)+htons(head->addNum);
	hook+=strlen(hook)+1;
	hook+=2*sizeof(short);
	struct timeval now;
    gettimeofday(&now,NULL);
    unsigned short type=0;
	while(rrNum>=1){
		hook+=downRR(res, hook, rRecord);
		fprintf(fp, "\n");
		nameSwitch(rRecord->name);
		fprintf(fp, "%s ",rRecord->name);
		long expire = now.tv_sec+htonl(rRecord->ttl);
		fprintf(fp, "%ld ", expire);
		type = htons(rRecord->type);
		switch(type){
			case A_TYPE:	fprintf(fp, "A IN "); break;
			case MX_TYPE:	fprintf(fp, "MX IN "); break;
			case CNAME_TYPE:fprintf(fp, "CNAME IN "); break;
			case PTR_TYPE:	fprintf(fp, "PTR IN "); break;
		}
		if(type==MX_TYPE){
			char container[128]; memset(container, 0, 128);
			memcpy(container, rRecord->rdata, sizeof(short));
			unsigned short preference=0;
			memcpy(&preference, container, sizeof(short));
			preference = htons(preference);
			memset(container, 0, 128);
			sprintf(container, "%hu", preference);
			fprintf(fp, "%s ", container); memset(container,0,128);
			memcpy(container, rRecord->rdata+sizeof(short), strlen(rRecord->rdata+sizeof(short))+1);
			nameSwitch(container);
			fprintf(fp, "%s ", container);
			fflush(fp);
		}else if(type==A_TYPE){
			char buf[100]; memset(buf, 0, 100);
			unsigned short num=0;
			num=rRecord->rdata[0];
			sprintf(buf, "%hu", num);
			fprintf(fp, "%s.",buf);
			num=rRecord->rdata[1];
			sprintf(buf, "%hu", num);
			fprintf(fp, "%s.",buf);
			num=rRecord->rdata[2];
			sprintf(buf, "%hu", num);
			fprintf(fp, "%s.",buf);
			num=rRecord->rdata[3];
			sprintf(buf, "%hu", num);
			fprintf(fp, "%s ",buf);
			fflush(fp);
		}else{
			nameSwitch(rRecord->rdata);
			fprintf(fp, "%s ",rRecord->rdata);
			fflush(fp);
		}
		rrNum--;
	}
	free(head);
	fclose(fp);
}

unsigned int searchCache(char *name, char *r, dns_header *head){
	char col[DNSMAXLEN]; memset(col, 0, DNSMAXLEN);
	unsigned short offset=0;
	struct timeval now;
    gettimeofday(&now,NULL);
    dns_rr *rRecord = (dns_rr *)malloc(sizeof(dns_rr));
    rRecord->name=NULL; rRecord->rdata=NULL;
    FILE *cache = fopen("cache.txt", "r");
	while(fgets(col, DNSMAXLEN-1, cache) != NULL){
		if(cmpDomainName(name, col, now.tv_sec)){
			head->answerNum++;
			
			char *p=col;
			unsigned int len=0;
			
			rRecord->name = (char *)malloc(3*sizeof(char));
			char *tmp = rRecord->name;
			tmp[0]=0xc0; tmp[1]=sizeof(dns_header); tmp[2]='\0';
			offset+=2;
			
			p+=blocklen(p); p+=blocklen(p);
			
			char container[128]; memset(container, 0, 128);
			
		 	len=blocklen(p);
		 	memcpy(container, p, len-1); container[len-1]='\0';
		 	p+=len;
		 	rRecord->type = htons(getType(container));
		 	memset(container, 0, len); offset+=sizeof(short);
		 	
		 	p+=blocklen(p);
		 	rRecord->rclass = htons(IN); offset+=sizeof(short);
		 	
		 	rRecord->ttl = 0;
		 	offset+=sizeof(int);
		 	
		 	if(rRecord->type == htons(MX_TYPE)){
	 			len = blocklen(p);
	 			memcpy(container, p, len-1);
	 			container[len-1]='\0';
	 			unsigned short preference = htons(atoi(container));
	 			memset(container, 0, len);
	 			p+=len;
	 			len=blocklen(p);
	 			memcpy(container, p, len-1); container[len-1]='\0';
	 			reverseNameSwitch(container);
	 			int datalen = strlen(container);
	 			rRecord->rdata = (char *)malloc((2+len+1)*sizeof(char));
	 			memcpy(rRecord->rdata, &preference, sizeof(short)); offset+=sizeof(short);
	 			memcpy(rRecord->rdata+sizeof(short), container, datalen+1);
	 			offset+=datalen+1;
	 			rRecord->data_len = htons(datalen+1+sizeof(short));
	 			offset+=sizeof(short);
	 		}else{
		 		len=blocklen(p);
	 			memcpy(container, p, len-1); container[len-1]='\0';
	 			if(rRecord->type == htons(A_TYPE)){
			 		rRecord->data_len=htons(4);
			 		in_addr_t addr = inet_addr(container);
			 		rRecord->rdata = (char *)malloc(4*sizeof(char));
			 		memcpy(rRecord->rdata, &addr, 4);
			 		offset+=sizeof(short)+4;
			 	}else{
	 				reverseNameSwitch(container);
	 				int datalen = strlen(container);
		 			rRecord->rdata = (char *)malloc((len+1)*sizeof(char));
		 			memcpy(rRecord->rdata, container, datalen+1);
		 			offset+=datalen+1;
		 			rRecord->data_len = htons(datalen+1);
		 			offset+=sizeof(short);
	 			}
		 	}
		 	r+=upRR(r, rRecord);
		 	initRR(rRecord);
		}
	}
	head->answerNum = htons(head->answerNum); 
	free(rRecord);
	fclose(cache);
	return offset;
}

unsigned int upRR(char *r, dns_rr *rRecord){
	int len;
	int offset=0;
	len=strlen(rRecord->name);
	if(rRecord->name[0]==0xc0){
		memcpy(r, rRecord->name, len);
		r += len; offset+=len;
	}else{
		memcpy(r, rRecord->name, len+1);
		r += len+1; offset+=len+1;
	}
	memcpy(r, &(rRecord->type), 3*sizeof(short)+sizeof(int));
	r+=3*sizeof(short)+sizeof(int); offset+=3*sizeof(short)+sizeof(int);
	char *tmp=rRecord->rdata;
	if(rRecord->type==htons(A_TYPE)){
		memcpy(r, tmp, 4);
		offset+=4;
	}else{
		if(rRecord->type==htons(MX_TYPE)){
			memcpy(r, tmp, sizeof(short));
			r+=sizeof(short);offset+=sizeof(short);tmp+=sizeof(short);
			if(tmp[0]==0xc0){
				memcpy(r, tmp, 2);
				offset+=2;
			}else{
				len=strlen(tmp);
				memcpy(r, tmp, len+1);
				offset+=len+1;
			}
		}else{
			if(tmp[0]==0xc0){
				memcpy(r, tmp, 2);offset+=2;
			}else{
				len=strlen(tmp);
				memcpy(r, tmp, len+1);
				offset+=len+1;
			}
		}
	}
	return offset;
}

unsigned short getType(char *ch){
	if(ch[0]=='M') return MX_TYPE;
	if(ch[0]=='A') return A_TYPE;
	if(ch[0]=='C') return CNAME_TYPE;
	if(ch[0]=='P') return PTR_TYPE;
	return 0;
}

unsigned int UDPConnection(in_addr_t addr, char *content, int contentLen, char *result){
	int s;
	struct sockaddr_in addr_serv;
	struct sockaddr_in addr_clie;
	int len = sizeof(addr_clie);
	s=socket(AF_INET, SOCK_DGRAM, 0);
	memset(&addr_serv,0,sizeof(addr_serv));
	addr_serv.sin_family = AF_INET;
	addr_serv.sin_addr.s_addr = addr;
	addr_serv.sin_port=htons(PORT);
	sendto(s, content, contentLen, 0, (struct sockaddr*)&addr_serv, sizeof(addr_serv));
	return recvfrom(s,result,DNSMAXLEN,0,(struct sockaddr*)&addr_clie, &len);
}

unsigned int downHead(char *q, dns_header *head){
	memcpy(head,q,sizeof(dns_header));
	return sizeof(dns_header);
}

unsigned int downQuery(char *q, dns_query *query){
	int len = strlen(q)+1;
	query->name = (char *)malloc(len*sizeof(char));
	memcpy(query->name, q, len);
	q += len;
	memcpy(&(query->qtype), q, 2*sizeof(short));
	return len + 2*sizeof(short);
}

int cmpDomainName(char *name, char *col, long nowsec){
	int len = strlen(name),i=0;
	while(i<len){
		if(name[i]!=col[i]){return 0;}
		i++;
	}
	if(col[i]!=' ') {return 0;}
	else {
		len = blocklen(col+i+1);
		char strtime[len]; memset(strtime, 0, len);
		memcpy(strtime, col+i+1, len-1); strtime[len-1]='\0';
		long expire = atol(strtime);
		if(expire>nowsec) return 1;
		else return 0;
	}
}

unsigned int upQuery(char *r, const dns_query *query){
	int len = strlen(query->name)+1;
	memcpy(r, query->name, len);
	r += len;
	memcpy(r, &(query->qtype), 2*sizeof(short));
	return len + 2*sizeof(short);
}

int blocklen(char *cur){
	int i=0;
	while(1){
		if(cur[i]==' ')
			break;
		else i++;
	}
	return i+1;
}

char * reverseNameSwitch(char *name){
	int i=1, len=strlen(name);
	char count=0, cur=0;
	char tmp[len+1];
	memcpy(tmp, name, len+1);
	memcpy(name+1, tmp, len+1);
	len=strlen(name);
	while(i<=len){
		if(name[i]=='.'||name[i]=='\0'){
			name[cur]=count;
			cur+=count+1;
			count=0;
		}else{
			count++;
		}
		i++;
	}
	return name;
}

char * nameSwitch(char *name){
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

unsigned int downRR(char *buf, char *cur, dns_rr *rRecord){
	unsigned int offset = 0;
	int len = 0;
	char pointer=0xc0;
	if(cur[0]==pointer){
		char *tmp=cur;
		cur = buf+cur[1];
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