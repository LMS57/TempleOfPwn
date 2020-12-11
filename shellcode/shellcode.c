#include <stdio.h>
#include <sys/socket.h> //For Sockets
#include <stdlib.h>
#include <netinet/in.h> //For the AF_INET (Address Family)
#include <sys/types.h>
#include <unistd.h>
#include "seccomp-bpf.h"

struct sockaddr_in serv; //This is our main socket variable.
int fd; //This is the socket file descriptor that will be used to identify the socket
int conn; //This is the connection file descriptor that will be used to distinguish client connections.

static int easy_filter(void)
{
	struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		DISALLOW_SYSCALL(execve),
		ALLOW_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("prctl(NO_NEW_PRIVS)");
		goto failed2;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		printf("prctl(SECCOMP)");
		printf("Test\n");
		goto failed2;
	}
	return 0;

failed2:
	if (errno == EINVAL){
		printf("SECCOMP_FILTER is not available. :(\n");
		exit(0);
	}
	return 1;
}


static int difficult_filter(void)
{
	struct sock_filter filter[] = {
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		DISALLOW_SYSCALL(execve),
		DISALLOW_SYSCALL(execveat),
		DISALLOW_SYSCALL(open),
		DISALLOW_SYSCALL(openat),
		ALLOW_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		printf("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL){
		printf("SECCOMP_FILTER is not available. :(\n");
		exit(0);
	}
	return 1;
}

static int good_luck_filter(void)
{
	struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(dup),
		ALLOW_SYSCALL(dup2),
		ALLOW_SYSCALL(mprotect),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(stat),
		ALLOW_SYSCALL(kill),
		ALLOW_SYSCALL(getppid),
		ALLOW_SYSCALL(getpid),
		KILL_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		printf("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		printf("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL){
		printf("SECCOMP_FILTER is not available. :(\n");
		exit(0);
	}
	if(errno)
		return 1;
	else
		asm("jmp %RSP");
}


void setup(){
	serv.sin_family = AF_INET;
	serv.sin_port = htons(8096); //Define the port at which the server will listen for connections.
	serv.sin_addr.s_addr = INADDR_ANY;
	fd = socket(AF_INET, SOCK_STREAM, 0); //This will create a new socket and also return the identifier of the socket into fd.
	// To handle errors, you can add an if condition that checks whether fd is greater than 0. If it isn't, prompt an error
	while(1){
		int t = bind(fd, (struct sockaddr *)&serv, sizeof(serv)); //assigns the address specified by serv to the socket
		if(t == 0){
			break;
		}
		printf("Problem with setting up the port\n");
		exit(0);
	}
	listen(fd,5); //Listen for client connections. Maximum 5 connections will be permitted.
	return;
}

int main(){
	char message[16] = ""; //This array will store the messages that are sent by the server
	setup();
	int difficulty;
	printf("How difficult should this be?\n");
	scanf("%d",&difficulty);
	printf("%s\n", difficulty?difficulty>1?difficulty==1337?"Only You know what you are capable of":"Execve, Execveat, open, and openat are all blocked":"Execve Will be Blocked":"NO Seccomp Filter applied");

//Now we start handling the connections.
while(conn = accept(fd, (struct sockaddr *)NULL, NULL)) {
    int pid;
    if((pid = fork()) == 0) {
	switch(difficulty){
		default:
			break;
		case 1:
			easy_filter();

			break;
		case 2:
			difficult_filter();
			break;
		case 1337:
			read(conn,message,250);
			good_luck_filter();

		

	}
	printf("Connected\n");
	if(difficulty != 1337)
		while (read(conn, message, 56)>0) {
			if(!strncmp("done", message,4))
				return 0;
		    	printf("Message Received: %s\n", message);
		}
    }
}

}
