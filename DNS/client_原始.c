#include"dnshead.h"
#include"DNScln.h"
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

unsigned char * nameSwitch(char * name, int len){
	printf("%s %d\n",name, len);
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
	printf("%s\n",buf);
	return buf;
}

int parseOrder(dns_query *question, int argc, char *argv[]){
	question->qclass = 0;
	if(argc == 2){
		question->name = nameSwitch(argv[1], strlen(argv[1]));
		question->qtype = 1;
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

void initQueryHead(dns_header *head){
	head->id = 1;
	head->queryNum = 1;
}





