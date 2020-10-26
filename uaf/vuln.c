#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void getFlag()
{
	execlp("cat","cat","flag.txt",NULL);
}

void admin_info()
{
	puts("I am an admin");
}

typedef struct{
	void (*flag)();
	void (*info)();
} admin_struct, *admin;

typedef struct {
	char name[16];
} student_struct, *student;


int main()
{
	int choice;
	student new_student = NULL;
	admin new_admin = NULL;

	while(1)
	{
		puts("MENU");
		puts("1: Make new admin");
		puts("2: Make new user");
		puts("3: Print admin info");
		puts("4: Edit Student Name");
		puts("5: Print Student Name");
		puts("6: Delete admin");
		puts("7: Delete user");
		printf("\nChoice: ");
		fflush(stdout);
		scanf("%d%*c", &choice);
		if(choice == 1)
		{
			new_admin = malloc(sizeof(admin_struct));
			new_admin->info = admin_info;
			new_admin->flag = getFlag;
		}
		else if(choice == 2)
		{
			new_student = malloc(sizeof(student_struct));
			printf("What is your name: ");
			fflush(stdout);
			read(0,new_student->name,16);
		}
		else if(choice == 3)
			new_admin->info();
		else if(choice == 4){
			printf("What is your name: ");
			fflush(stdout);
			read(0,new_student->name,16);
			
		}
		else if(choice == 5){
			if(new_student == NULL){
				printf("New student has not been created yet\n");
			}
			else{
				printf("Students name is %s\n",new_student->name);
			}
			
		}
		else if(choice == 6)
		{
			free(new_admin);
		}
		else if(choice == 7)
			free(new_student);
		else
			puts("bad input");
	}


	return 0;
}

