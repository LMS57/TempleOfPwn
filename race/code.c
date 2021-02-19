#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>


char *notes[15] = {0};
int *sizes[15] = {0};

#define PORT 1337

char *menu = "What would you like to do:\n\
1. Create Note\n\
2. Edit Note\n\
3. Delete Note\n\
4. Exit\n";
char *unknown = "Unknown Command\n";
int print_menu(new_socket){
		write(new_socket, menu,strlen(menu));
}

unsigned int choice;
char buffer[1024];

char *size = "What size of note would you like to create: ";
char *large = "That is too large of a note, below 1024 only\n";
int create(new_socket){
		int x = 0;

		for(x = 0 ; x < 15 ; x++){
			if (notes[x] == 0)
					break;
		}
		if(x == 15){
			return 0;
		}

		while(1){
				write(new_socket,size,strlen(size));
				read(new_socket,buffer,10);
				choice = atoi(buffer);

				if (choice < 1025){
						break;
				}
				write(new_socket,large,strlen(large));
		}	
		sizes[x] = choice;
		notes[x] = malloc(choice);
		return 0;
	
}

char *index="What index would you like to edit: ";
char *data="What data would you like to put in this index: ";

int edit(new_socket){
	write(new_socket, index, strlen(index));
	read(new_socket, buffer, 5);
	choice = atoi(buffer);

	if (notes[choice] != 0){
		write(new_socket, data, strlen(data));
		read(new_socket, notes[choice], sizes[choice]); 
	}	
	return 0;

}
char *del_index="What index would you like to delete: ";
char *one_last="Would you like to see your data one last time before it is gone forever (y,n): ";

int delete(new_socket){
	write(new_socket, del_index, strlen(del_index));
	read(new_socket, buffer, 5);
	choice = atoi(buffer);
	char buffer2[1030];
	if (notes[choice] != 0){
		strcpy(buffer2,notes[choice]);
		free(notes[choice]);

		write(new_socket, one_last, strlen(one_last));
		read(new_socket, buffer, 2);
		if (buffer[0] == 'y'){
			write(new_socket, buffer2, strlen(buffer2));
		}
		notes[choice] = 0;
	}	
	return 0;
}

int vuln(new_socket){
		while(1){
				print_menu(new_socket);

				read(new_socket,buffer,5);
				choice = atoi(buffer);
				
				switch(choice){
					case 1:
							create(new_socket);
							break;
					case 2:
							edit(new_socket);
							break;
					case 3:
							delete(new_socket);
							break;
					case 4:
							return 0;
					default:
							write(new_socket,unknown,strlen(unknown));
				}
		}


}

int main(){
	int server_fd, new_socket, valread; 
	struct sockaddr_in address; 
    int opt = 1; 
	pthread_t thread;
    int addrlen = sizeof(address); 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
	while(1){
			if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
							   (socklen_t*)&addrlen))<0) 
			{ 
				perror("accept"); 
				continue;
			} 
			pthread_create(&thread,	NULL, vuln, (void *)new_socket);
		}
    return 0; 

}
