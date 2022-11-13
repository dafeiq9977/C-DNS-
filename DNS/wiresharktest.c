#include"dnshead.h"

int main(int argc, char *argv[]){
	int ss, sc;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	ss = socket(AF_INET, SOCK_STREAM, 0);
	if(ss<0){
		printf("ss error\n");
	}
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.2");
	server_addr.sin_port = htons(53);
	int err = bind(ss, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if(err<0){
		printf("bind error!err=%d\n",err);
		perror("reason:");
	}
	err = listen(ss, 5);
	for(;;){
		socklen_t addrlen = sizeof(struct sockaddr);
		sc = accept(ss, (struct sockaddr *)&client_addr, &addrlen);
		char buf[1024];
		int i=0, size=35, read_len;
		
		read_len = recv(sc, buf, 100, 0);
		int tmp = 0;
		printf("%d\n",read_len);
		for(i=0; i<size; i++){
			tmp = buf[i];
			printf("%c ",tmp);
		}
		printf("hello");
		//close(sc);
	}
	close(ss);
}
