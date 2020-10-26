#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int win(){
	puts("No one should get here");
}

int main(){
	char s[100];
	read(0,s,100);
	printf(s);
	fflush(stdout);
	exit(0);//no return
}
