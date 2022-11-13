/*
 * this file includes server code
 * written by Qu Peiran on 2020.6.1
 * using blank line to seperate different part
 */
#include"dnshead.h"
#include"server.h"
#include"tree.h"
#define PORT_SERV 53

int main(int argc, char *argv[]){
	//initializing UDP connection
	int s;
	struct sockaddr_in addr_serv, addr_clie;
	int addr_clie_len=sizeof(addr_clie);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&addr_serv, 0, sizeof(addr_serv));
	addr_serv.sin_family = AF_INET;
	addr_serv.sin_addr.s_addr = inet_addr("127.0.0.3");			//allocate 127.0.0.3 to this server
	addr_serv.sin_port = htons(PORT_SERV);
	bind(s, (struct sockaddr *)&addr_serv, sizeof(addr_serv));
	
	/*
	 * buf  : char[]	receive bytes from local server
	 * res  : char[]	buffer to hold DNS response packet
	 * q    : char*	point to next byte to be processed
	 * r    : char*	point to next byte to be written
	 * query: dns_query*	store query section in request packet
	 * head : dns_header*	store head section in request packet
	 * rRecord: dns_rr*	store resource records in response packet
	 * ansnum, authnum, addnum : int	store numbers of answer, author and addtion section
	 * offset : int	 store response packet length
	 * servers : nextserver*	store all information of next server managed by this server	
	 * row : int	numbers of the next servers
	 * dictree : tree	server dictionary tree
	 */
	char buf[DNSMAXLEN]; memset(buf, 0, DNSMAXLEN);
	char res[DNSMAXLEN]; memset(res, 0, DNSMAXLEN);
	char *q=NULL;
	char *r=NULL; 
	dns_query *query = (dns_query *)malloc(sizeof(dns_query));
	dns_header *head = (dns_header *)malloc(sizeof(dns_header));
	dns_rr *rRecord = (dns_rr *)malloc(sizeof(dns_rr));
	unsigned short ansnum=0, authnum=0, addnum=0;
	int offset=0; 
	nextserver *servers = NULL;
	tree dictree;
	int row=0;
	
	// main server business logic 
	while(1){
		q=buf; r=res; ansnum=0; authnum=0; addnum=0;
		//accept requests
		int size = recvfrom(s, buf, DNSMAXLEN, 0, (struct sockaddr*)&addr_clie, &addr_clie_len);
		int i;
		//initialize dictionary tree
		initTree(&dictree);
		//copy down head section from request packet to head structure
		q += downHead(q,head);
		unsigned short qNum = htons(head->queryNum);
		//find answers for each query
		while(qNum>0){
			// copy down query section to query structure
			q += downQuery(q, query); 
			// skip head section and write response head last
			r += sizeof(dns_header);
			// copy query section to response buffer
			r += upQuery(r, query); offset = r-res;
			//insert the query name into the tree
			insertWord(&dictree, nameSwitch(query->name), sizeof(dns_header));
			
			//get query type and open corresponding file
			unsigned short type = htons(query->qtype);
			char *filePath = NULL;
			switch(type){ 
				case A_TYPE: filePath = "3A.txt"; break;
				case CNAME_TYPE: filePath = "3CNAME.txt"; break;
				case MX_TYPE: filePath = "3MX.txt"; break;
				case PTR_TYPE: filePath = "3PTR.txt"; break;
			}
			FILE *fp = fopen(filePath, "r");
			char col[DNSMAXLEN]; memset(col, 0, DNSMAXLEN);
			// match each row to query name
			while(fgets(col, DNSMAXLEN-1, fp) != NULL){ 
				if(compare(query, col)){
					offset = getAnswerRR(col, rRecord, query, &dictree, offset);
					ansnum++;
					r += upRR(r,rRecord);
					// if query type is MX, we nead to find its A resource record as well
					if(type==MX_TYPE){
						query->qtype=htons(A_TYPE);
						nameSwitch(rRecord->rdata+sizeof(short));
						FILE *mx = fopen("3A.txt", "r");
						while(fgets(col, DNSMAXLEN-1, mx) != NULL){
							if(cmpDomainName(rRecord->rdata+sizeof(short), col)){
								dns_rr *answerRR = (dns_rr *)malloc(sizeof(dns_rr)); 
								offset = getAnswerRR(col, answerRR, query, &dictree, offset);
								addnum++;
								r += upRR(r,answerRR);
								initRR(answerRR);
							}
						}
						query->qtype=htons(MX_TYPE);
						fclose(mx);
					}
					initRR(rRecord);
				}
			}
			memset(col,0,DNSMAXLEN);
			fclose(fp);
			
			// if no answer is found, try to find the next server
			if(!ansnum){
				// server == NULL indicates this is the first request
				// all the information of the next server should load to memory
				if(servers==NULL){
					fp = fopen("nextserver3.txt","r");
					while(fgets(col, DNSMAXLEN-1, fp)!=NULL){row++;}
						fseek(fp, 0L, SEEK_SET);
						servers = (nextserver *)malloc(row*sizeof(nextserver));
						row=0;
						while(fgets(col, DNSMAXLEN-1, fp)!=NULL){
							initServerInfo((servers+row), col);
							row++;
						}
					fclose(fp);
				}
				int tmp=offset;
				offset=addAuthor(query->name, servers, row, rRecord, &dictree, offset, r);
				if(offset>tmp){
					authnum=1, addnum=1;
				}
			}
			
			// fill head section respectively
			head->id=htons(1);
			head->authorNum=htons(authnum);head->addNum=htons(addnum);
			head->answerNum=htons(ansnum);
			if(ansnum){
				head->tag = htons(0 | QR | AA | SUCCESS);
			}else if(authnum){
				head->tag = htons(0 | QR | AA | NOT_EXIST);
			}else{
				head->tag = htons(0 | QR | NOT_EXIST);
			}
			memcpy(res, head, sizeof(dns_header));
			
			//send to local server
			sendto(s, res, offset, 0, (struct sockaddr *) &addr_clie, sizeof(addr_clie));
			
			// release memory
			initHead(head);initQuery(query);initRR(rRecord);
			qNum--;
		}
		memset(buf, 0, size);
		// empty tree when finished 
		destroyTree(&dictree);
	};
	free(head);free(query);free(rRecord);
	free(servers);
}

// this function return word length plus 1(blank space counts)
// e.g hello world  return 6 for the first word
int blocklen(char *cur){
	int i=0;
	while(1){
		if(cur[i]==' ')
			break;
		else i++;
	}
	return i+1;
}

// this function upload contents in dns_rr structure to response buffer
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

// this function check the next server name matches the query name
int isMatch(char *qName, char *serName){
	int qLen=strlen(qName), serLen=strlen(serName);
	if(qLen<=serLen) return 0;
	while(serLen>=0){
		if(qName[qLen]!=serName[serLen]) return 0;
		qLen--; serLen--;
	}
	return qName[qLen]=='.'? 1:0;
}

// this function put next server answer and its IP address to response buffer
unsigned int addAuthor(char *qName, nextserver *servers, int row, dns_rr *rRecord, tree *dictree, int offset, char *r){
	int i=0;
	int len=0;
	int getoffset = 0;
	while(i<row){
		if(rRecord->rclass==0){
			if(isMatch(qName, (servers+i)->domain)){
				if(getoffset=insertWord(dictree, (servers+i)->domain, offset)){
					rRecord->name = (char *)malloc(3*sizeof(char));
					unsigned char *tmp = rRecord->name;
					tmp[2]='\0';tmp[0]=0xc0;tmp[1]=getoffset;
					offset+=2;
				}else{
					len = strlen((servers+i)->domain)+2;
					rRecord->name = (char *)malloc(len*sizeof(char));
					memcpy(rRecord->name, (servers+i)->domain, len-1);
					reverseNameSwitch(rRecord->name);
					offset+=len;
				}
				rRecord->type = htons(NS_TYPE); offset+=sizeof(short);
				rRecord->rclass = htons(1); offset+=sizeof(short);
				rRecord->ttl = 0; offset+=sizeof(int);
				if(getoffset=insertWord(dictree, (servers+i)->ser_name, offset+2)){
					rRecord->data_len = htons(2); offset+=sizeof(short);
					rRecord->rdata = (char *)malloc(3*sizeof(char));
					unsigned char *tmp = rRecord->rdata;
					tmp[2]='\0';tmp[0]=0xc0;tmp[1]=getoffset;
					offset+=2;
				}else{
					len = strlen((servers+i)->ser_name)+2;
					rRecord->data_len = htons(len); offset+=sizeof(short);
					rRecord->rdata = (char *)malloc(len*sizeof(char)); 
					memcpy(rRecord->rdata, (servers+i)->ser_name, len-1);
					reverseNameSwitch(rRecord->rdata);
					offset+=len;
				}
				r += upRR(r, rRecord);
				if(getoffset=insertWord(dictree, nameSwitch(rRecord->rdata), offset)){
					r[0]=0xc0; r[1]=getoffset; r+=2;offset+=2;
				}else{
					reverseNameSwitch(rRecord->rdata);
					int domainNameLen = strlen(rRecord->rdata)+1;
					memcpy(r, rRecord->rdata, domainNameLen);
					r+=domainNameLen; offset+=domainNameLen;
				}
				rRecord->type=htons(A_TYPE);
				rRecord->rclass=htons(IN);
				memcpy(r, &rRecord->type, 3*sizeof(short)+sizeof(int));
				r+=3*sizeof(short)+sizeof(int);offset+=3*sizeof(short)+sizeof(int);
				in_addr_t addr = inet_addr((servers+i)->IP_addr);
				memcpy(r, &addr, sizeof(addr)); r+=sizeof(addr);offset+=sizeof(addr);
				offset+=sizeof(addr);
				break;
			}
		}else printf("addAuthor error!\n");
		i++;
	}
	return offset;
}

// load the next level server information to memory
void initServerInfo(nextserver *servers, char *col){
	char *cur=col;
	int len = blocklen(cur);
	if(len){
		servers->domain = (char *)malloc(len*sizeof(char)); 
		memcpy(servers->domain, cur, len-1);
		servers->domain[len-1]='\0';
		cur+=len;
	}
	len = blocklen(cur);
	if(len){
		servers->ser_name = (char *)malloc(len*sizeof(char)); 
		memcpy(servers->ser_name, cur, len-1);
		servers->domain[len-1]='\0';
		cur+=len;
	}
	len = blocklen(cur);
	if(len){
		servers->IP_addr = (char *)malloc(len*sizeof(char)); 
		memcpy(servers->IP_addr, cur, len-1);
		servers->domain[len-1]='\0';
		cur+=len;
	}
	return;
}

// determine if the server is big endian or small endian
int isBigEndien(){
	union{
		short s;
		char c[sizeof(short)];
	}un;
	un.s=0x0102;
	if(sizeof(short)==2){
		if(un.c[0]==1&&un.c[1]==2)
			return 1;
		else
			return 0;
	}else{
		printf("unknow endien");
		return 0;
	}
}

// copy head section in request packet to dns_header structure
unsigned int downHead(char *q, dns_header *head){
	memcpy(head,q,sizeof(dns_header));
	return sizeof(dns_header);
}

// copy query section in request packet to dns_query structure
unsigned int downQuery(char *q, dns_query *query){
	int len = strlen(q)+1;
	query->name = (char *)malloc(len*sizeof(char));
	memcpy(query->name, q, len);
	q += len;
	memcpy(&(query->qtype), q, 2*sizeof(short));
	return len + 2*sizeof(short);
}

// upload the dns_query structure to response buffer
unsigned int upQuery(char *r, const dns_query *query){
	int len = strlen(query->name)+1;
	memcpy(r, query->name, len);
	r += len;
	memcpy(r, &(query->qtype), 2*sizeof(short));
	return len + 2*sizeof(short);
}

// find if the query matches this resource record
unsigned int compare(const dns_query *query, const char *col){
	unsigned int offset = 0;
	if(offset = cmpDomainName(query->name,col)){
 		if(cmpTypeClass(query->qtype, col+offset))
			return 1;
		else return 0;
	}
	return 0;
}

// find if domain name matches this resource record
unsigned int cmpDomainName(const char *name, const char *col){
	int len = strlen(name),i=0;
	while(i<len){
		if(name[i]!=col[i]){return 0;}
		i++;
	}
	if(col[i]!=' ') return 0;
	else return len+1;
}

// find if the class matches this resource record
unsigned int cmpTypeClass(const unsigned short type, const char *col){
	return 1;
}

// get resource record and write it to response buffer
unsigned int getAnswerRR(char *col, dns_rr *rRecord, dns_query *query, tree *dictree, int offset){
	char *cur = col;
	unsigned int len = 0;
	int getoffset;
	
	len = blocklen(cur);
	char name[len+1]; memcpy(name, cur, len-1);name[len-1]='\0';
	if(getoffset=insertWord(dictree, name, offset)){
		rRecord->name = (char *)malloc(3*sizeof(char));
		unsigned char *tmp = rRecord->name;
		tmp[2]='\0';tmp[0]=0xc0;tmp[1]=getoffset;
		cur += len;
		offset += 2;
	}else{
		rRecord->name = (char *)malloc((len+1)*sizeof(char));
		memcpy(rRecord->name, cur, len-1);
		reverseNameSwitch(rRecord->name);
		cur += len;
		offset += len+1;
	} 
	rRecord->type = query->qtype; rRecord->rclass = query->qclass;
	cur += blocklen(cur); cur += blocklen(cur);
	offset += 2*sizeof(short); 
	len = blocklen(cur);
	char strttl[len]; 
	memcpy(strttl, cur, len-1); strttl[len-1]='\0'; cur += len;
	int TTL = atoi(strttl);
	rRecord->ttl = htoni(TTL); offset += sizeof(int);
	if(query->qtype != htons(A_TYPE)){
		if(query->qtype == htons(MX_TYPE)){ 
			len = blocklen(cur);
			char strpreference[len];
			memcpy(strpreference, cur, len-1); strpreference[len-1]='\0';
			unsigned short preference = htons(atoi(strpreference));
			cur += len; offset+=sizeof(short);    
		 	len = blocklen(cur);
			char data[len+1]; memcpy(data, cur, len-1); data[len-1]='\0';
			if(getoffset=insertWord(dictree, data, offset+2)){ 
				rRecord->data_len = htons(2+sizeof(short));
				rRecord->rdata = (char *)malloc((sizeof(short)+3)*sizeof(char));
				unsigned char *tmp = rRecord->name;
				memcpy(tmp,&preference,sizeof(short));
				tmp[4]='\0';tmp[2]=0xc0;tmp[3]=getoffset;
				offset+=2+sizeof(short);
			}else{ 
				reverseNameSwitch(data);
				rRecord->data_len = htons(len+1+sizeof(short));		
				rRecord->rdata = (char *)malloc((sizeof(short)+len+1)*sizeof(char));
				unsigned char *tmp = rRecord->rdata;
				memcpy(tmp,&preference,sizeof(short));
				memcpy((tmp+sizeof(short)), data, len+1);
				offset+=len+1+sizeof(short);
			}
		}else{
			len = blocklen(cur);
			char data[len+1]; memcpy(data, cur, len-1); data[len-1]='\0';
			if(getoffset=insertWord(dictree, data, offset+2)){ 
				rRecord->data_len = htons(2);
				rRecord->rdata = (char *)malloc(3*sizeof(char));
				unsigned char *tmp = rRecord->name;
				tmp[2]='\0';tmp[0]=0xc0;tmp[1]=getoffset;
				offset+=2+sizeof(short);
			}else{ 
				reverseNameSwitch(data);
				rRecord->data_len = htons(len+1);
				rRecord->rdata = (char *)malloc((len+1)*sizeof(char));
				memcpy(rRecord->rdata, data, len);
				(rRecord->rdata)[len] = '\0';
				offset+=len+1+sizeof(short);
			}
		}
	}else{
		rRecord->data_len = htons(4);
		offset+=sizeof(short);
		rRecord->rdata = (char *)malloc(4*sizeof(char));
		char *tmp = rRecord->rdata;
		len = blocklen(cur);
		char ipvf[len]; memcpy(ipvf, cur, len-1); ipvf[len-1]='\0';
		in_addr_t addr = inet_addr(ipvf);
		offset+=4;
		memcpy(tmp, &addr, 4);
	} 
	return offset;	
}

// change the normal string to DNS format
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

// change DNS string back to the normal string
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

// switch integer
int htoni(int a){
	if(isBigEndien()) return a;
	char *start = (char *)&a;
	char tmp = 0;
	tmp=start[0];
	start[0]=start[3];
	start[3]=tmp;
	tmp=start[1];
	start[1]=start[2];
	start[2]=tmp;
	return a;
}












