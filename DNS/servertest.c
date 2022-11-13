#include"dnshead.h"

int main(){
	int s;
	struct sockaddr_in addr_serv;
	struct sockaddr_in addr_clie;
	int len = sizeof(addr_clie);
	s=socket(AF_INET, SOCK_DGRAM, 0);
	memset(&addr_serv,0,sizeof(addr_serv));
	addr_serv.sin_family = AF_INET;
	addr_serv.sin_addr.s_addr = inet_addr("127.0.0.2");
	addr_serv.sin_port=htons(53);
	char buf[]={
		0,1,0,0,0,1,0,0,0,0,0,0,3,'w','w','w',5,'b','a','i','d','u',3,'c','o','m',0,0,5,0,1
	};
	char res[512];memset(res,0,512);
	sendto(s, buf, 31, 0, (struct sockaddr*)&addr_serv, sizeof(addr_serv));
	recvfrom(s,res,512,0,(struct sockaddr*)&addr_clie, &len);
	int i=0;
	for(;i<100;i++){
		printf("%d ",res[i]);
	}
	printf("\n");
}
