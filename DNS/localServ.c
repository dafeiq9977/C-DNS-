#include "DNS.h"
#include "dnshead.h"
#include "LocalNameServ.h"

int main(void)
{
	int servSock, clntSock;
	int recvLen;
	struct sockaddr_in clntAddr;
	socklen_t clntAddrLen;
	dns_query clntQuery;
	//char dnsMsg[DNSMAXLEN];
	char *dnsMsg;

	servSock = initServer();
	while (1)
	{
		if ((listen(servSock, 1)) < 0)
		{
			printf("listen() failed.\n");
			exit(1);
		}
		memset(&clntAddr, 0, sizeof(clntAddr));
		clntAddrLen = 1;
		if ((clntSock=accept(servSock, (struct sockaddr *)&clntAddr, &clntAddrLen)) < 0)
		{
			printf("accept() failed.\n");
			continue;
		}
		dnsMsg = (char *)malloc(DNSMAXLEN*sizeof(char));
		if ((recvLen=recv(clntSock, dnsMsg, DNSMAXLEN, 0)) < 0)
		{
			printf("recv() failed.\n");
			continue;
		}
		memset(&clntQuery, 0, sizeof(clntQuery));
		initQuery (&clntQuery);
		char *domainStr = getQuery(dnsMsg, &clntQuery, recvLen, 14);
		printf("%s\n", domainStr);
		dns_rr rRecord;
		memset(&rRecord, 0, sizeof(rRecord));
		initRR (&rRecord);

		// check the local cache
		if ((checkCache(domainStr, &clntQuery, &rRecord))==0)
		{
			printf("valid\n");
			dns_header respHead;
			memset(&respHead, 0, sizeof(respHead));
			initHead (&respHead);
			generateRespHead(dnsMsg, &respHead, 1, 0, 0);
			char *respBuf = (char *)malloc(DNSMAXLEN);
			unsigned int len = generateResponse(respBuf, respHead, clntQuery, rRecord, 1);
			if (send(clntSock, respBuf, strlen(respBuf), 0) != len)
				printf("Send response failed.\n");
			close(clntSock);
			continue;
		}
		else
		{
			printf("invalid\n");
			dns_header respHead;
			memset(&respHead, 0, sizeof(respHead));
			initHead (&respHead);
			generateRespHead(dnsMsg, &respHead, 0, 0, 0);
			char *respBuf = (char *)malloc(DNSMAXLEN);
			unsigned int len = generateResponse(respBuf, respHead, clntQuery, rRecord, 0);
			if (send(clntSock, respBuf, strlen(respBuf), 0) != len)
				printf("Send response failed.\n");
			close(clntSock);
			continue;
		}

		// query the root server
		
		close(clntSock);
	}
}

