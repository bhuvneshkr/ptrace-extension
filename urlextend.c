#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>

const int long_size = sizeof(long);

//Function to check the correct usage of program
void check_arguments(int argc){
	if(argc != 3 ){
		printf("Incorrect number of arguments, please check.\n");
		printf("Correct usage: <filename> <argv1> <url_name>\n");
		exit(0);
	}
	return;
}


//Function to edit values in the regsiter i.e. place local file name inplace of URL given as input
void edit_register_data(char *str, char *in_url, char *localfile)
{  
    int check_str;
    check_str=strcmp(str,in_url);  // comparing string with URL, if found same replace with local file name (saved)
    if (check_str == 0){
	strcpy(str,localfile);
    }
    str[strlen(str)]='\0';
}

//Function to store the data received by PTRACE_PEEKDATA
void getdata(pid_t child, long addr,char *str)
{   char *laddr;
    int i;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    laddr = str;
    data.val = ptrace(PTRACE_PEEKDATA,child, addr + i * 4, NULL); //PTRACE_PEEKDATA used to get data 4 char each time
    do{
        memcpy(laddr, data.chars, long_size);  // copying data by 4-4 char each time to memory
        ++i;
        laddr += long_size;
	data.val = ptrace(PTRACE_PEEKDATA,child, addr + i * 4, NULL);
    }while(data.val != -1 && strlen(data.chars) == 5);
 
    if(strlen(data.chars) !=0 && strlen(data.chars) !=5) {  //appending remaining characeters (if <4 to the memory/regsiters)
	memcpy(laddr, data.chars, strlen(data.chars));
    }
    
    str[strlen(str)] = '\0';  //Adding terminating character at end
}

//Function to write str to the register (i.e. edited string we modified earlier will be overwritten using this function)
void putdata(pid_t child, long addr,char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
	memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,addr + i * 4, data.val); // Using PTRACE_POKEDATA to write the data from memory (laddr) to data.chars)
        ++i;
        laddr += long_size;
    }
}

// Main function

int main(int argc, char *argv[]){

	//Taking input

	FILE *fptr = NULL;

	check_arguments(argc);
	printf("Command : %s\n",argv[1]);
	printf("Url: %s\n",argv[2]);
	
	// Shell command to download the webpage using wget 
	char cmd[100]="wget ";
	strcat(cmd,argv[2]);
	system(cmd);

	// Looking for the latet web page downloaded
	char latest_webpage[20];
	system("find * -name \"*.html*\" | sort | tail -1 > latest_webpage");
	fptr = fopen("latest_webpage", "r");
  	fscanf(fptr, "%s", latest_webpage);

	pid_t child;
	child=fork();
	struct user_regs_struct regs;

	// Checking for different commands input 
	if(child == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
     		 
     		if(strcmp(argv[1],"wc") == 0){
			execl("/usr/bin/wc", "wc",argv[2], NULL);
		}
		else if(strcmp(argv[1],"cat") == 0){
			execl("/bin/cat", "cat",argv[2], NULL);
		}
		else if(strcmp(argv[1],"vi") == 0){
			execl("/usr/bin/vi", "vi",argv[2], NULL);
		}
		else if(strcmp(argv[1],"more") == 0){
			execl("/bin/more", "more",argv[2], NULL);
		}
		else if(strcmp(argv[1],"less") == 0){
			execl("/bin/less", "less",argv[2], NULL);
		}
		else if(strcmp(argv[1],"nano") == 0){
			execl("/bin/nano", "nano",argv[2], NULL);
		}
		/*/usr/bin/vi /bin/cat*/
		else{
			printf("Command not covered!!!\n");
			exit(0);
		}
	}
	else {
        	long orig_eax;
      		long params[3];
      		int status;
      		char *str, *laddr;
      		char temp[4];
      		int toggle = 0;
      		while(1) {
        		wait(&status);
         		if(WIFEXITED(status))
             		break;
         		orig_eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL); //getting orig_eax to check is SYS_open or SYS_write or SYS_stat64
			ptrace(PTRACE_GETREGS,child, NULL, &regs);
        		/*if(orig_eax == SYS_stat64) {
            			if(toggle == 0) {
               				toggle = 1;
               				params[0] = ptrace(PTRACE_PEEKUSER,child, 4 * EBX,NULL);
               				str = (char *)calloc((0) , sizeof(char));
               				getdata(child, params[0], str);
					int orig_str_len=strlen(str);
					edit_register_data(str,argv[2],latest_webpage);
              		 		putdata(child, params[0], str,orig_str_len);
            			}
            			else {
               				toggle = 0;
            			}
        		}*/
			if(orig_eax == SYS_open) {
				if(toggle == 0) {
               				toggle = 1;
               				params[0] = ptrace(PTRACE_PEEKUSER,child, 4 * EBX,NULL); // using ebx register as data is in it only
               				str = (char *)calloc((0) , sizeof(char)); // using calloc for memory location
               				getdata(child, params[0], str);  // calling getdata to get characters by characters from ebx
					int orig_str_len=strlen(str);
					edit_register_data(str,argv[2],latest_webpage); // calling edit_register_data to modify str and place local file name in place of URL
              		 		putdata(child, params[0], str,orig_str_len);  // calling putdata function to write modified string to the register
            			}
            			else {
               				toggle = 0;
            			}
        		}
     			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
      		}	
   	}
   return 0;
}


