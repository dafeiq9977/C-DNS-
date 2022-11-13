#include <stdio.h>        // for printf()
#include <sys/time.h>    // for gettimeofday()
#include <unistd.h>        // for sleep()

int main()
{
    /*struct timeval start, end;
    gettimeofday( &start, NULL );
    printf("start : %d.%d\n", start.tv_sec, start.tv_usec);
    sleep(1);
    gettimeofday( &end, NULL );
    printf("end   : %d.%d\n", end.tv_sec, end.tv_usec);*/
	char *ltime = "18273637230";
	printf("%d\n",sizeof(long long));
	printf("long int=%ld, int=%d\n", atol(ltime),atoi(ltime));
    return 0;
}
