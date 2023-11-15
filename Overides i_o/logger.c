#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#define MAXS 0xFFF;

void updateLogFile( int uid,char *fname, char *d_and_t, int acc_type, int act_den, char *hash){

FILE *f;

f = fopen("file_logging.log", "a+");

fprintf(f, "%d\n", uid);
fprintf(f, "%d\n", acc_type);
fprintf(f, "%d\n", act_den);
fprintf(f, "%s\n", d_and_t);
fprintf(f, "%s\n", fname);
fprintf(f, "%s\n", hash);

fclose(f);

}

FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

/*uid*/
int uid = getuid();

int access_type;

/*date and time*/

time_t cur_time;
    char* time_str;

    cur_time = time(NULL);

    if (cur_time == ((time_t)-1))
    {
        (void) fprintf(stderr, "Failure to obtain the current time.\n");
        exit(EXIT_FAILURE);
    }

    
    time_str = ctime(&cur_time);

/*access type*/
//determine if the file exists
if(access(path, F_OK) == 0){
access_type = 1;
}else{
access_type = 0;
}

/*action denied flag*/
int action_denied;
//FILE * tempf = original_fopen(path,mode);
if(access_type == 1){
if ((strcmp(mode,"r"))==0 || (strcmp(mode,"w"))==0 || (strcmp(mode,"a"))==0){

if ((access (path, R_OK)==0 || (access (path, W_OK)==0){
action_denied = 0;
}
}else if(strcmp(mode,"r+"))==0 || (strcmp(mode,"w+"))==0 || (strcmp(mode,"a+"))==0){
if((access (path, R_OK)==0) && (access (path, W_OK)==0){
action_denied = 0;
}
}else{
action_denied = 1;
}

/*
if(tempf == NULL){
action_denied = 1;
}else{
action_denied = 0;
}*/

}

/*hash / fingerprint*/
unsigned char hash_value[MD5_DIGEST_LENGTH];
	unsigned char *buffer;
	int i;

		fseek(original_fopen_ret, 0, SEEK_END);
		int f_size = ftell(original_fopen_ret);
		rewind(original_fopen_ret);
		buffer=malloc(f_size+1);

	if (original_fopen_ret)
	{
		
		fread(buffer,1,f_size,original_fopen_ret);
		MD5((unsigned char*) buffer, f_size, hash_value);
	}
	else
	{

		for(i=0;i<MD5_DIGEST_LENGTH;i++){
			hash_value[i]=0;
}

	}

/*update the log file*/
updateLogFile(uid,path, time_str, access_type, action_denied, hash_value);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

int uid = getuid();

int access_type = 2;

/*date and time*/    
time_t cur_time;
    char* time_str;

    cur_time = time(NULL);

    if (cur_time == ((time_t)-1))
    {
        (void) fprintf(stderr, "Failure to obtain the current time.\n");
        exit(EXIT_FAILURE);
    }

    
    time_str = ctime(&cur_time);

/*hash / fingerprint*/

	fseek(stream, 0, SEEK_END);
	int f_size = ftell(stream);
	rewind(stream);

	unsigned char hash_value[MD5_DIGEST_LENGTH];
	unsigned char *buffer;


	buffer=malloc(f_size+1);
	fread(buffer,1,f_size,stream);
	MD5((unsigned char*) buffer, f_size, hash_value);

int action_denied;
/*action denied flag*/
if(!(original_fwrite_ret<nmemb)){
	action_denied=0;
}else{
	action_denied=1;
}

/*filename and path*/

	int fn = fileno(stream);

	char proclink[MAXS];
	char fname[MAXS];
	
	
	sprintf(proclink, "/proc/self/fd/%d", fn);
	ssize_t p = readlink(proclink,fname,MAXS);
	
    	fname[p] = '\0';

/*update the log file*/
updateLogFile(uid, fname, time_str, access_type, action_denied, hash_value);

	return original_fwrite_ret;
}


