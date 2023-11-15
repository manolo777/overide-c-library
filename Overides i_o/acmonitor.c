#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int checkfName(char **fnames, char *fname, int num){

int i;

for(i = 0;i<num;i++){
if(fnames[i] != NULL){
if(strcmp(fnames[i], fname)==0){
return 1;
}
}
}
return 0;
}

void addfName(char **fnames, char *fname, int num){

int i = 0;

while(fnames[i] != NULL && i<num){

i++;
}

if(fnames[i] == NULL){
fnames[i] = fname;//strcpy(fnames[i], fname);
}else{
printf("there is a problem...\n");
}

}

int retPosOfName(char **fnames, char *fname, int num){

int i;

for(i = 0;i<num;i++){
if(fnames[i] != NULL){
if(strcmp(fnames[i], fname)==0){
return i;
}
}
}
return -1;
}

int checkUid(int *uids, int number, int num){

int i;

for(i = 0;i<num;i++){
if(uids[i] != 0){
if(uids[i] == number){
return 1;
}
}
}
return 0;
}

int retPosOfUid(int *uids, int number, int num){

int i;

for(i = 0;i<num;i++){
if(uids[i] != 0){
if(uids[i] == number){
return i;
}
}
}
return 0;
}

void addUid(int *uids, int number, int num){

int i = 0;

while(uids[i] != 0 && i< num){
i++;
}

if(uids[i] == 0){
uids[i] = number;
}else{
printf("problem...\n");
}

}



void
list_unauthorized_accesses(FILE* log)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */
FILE *f = fopen("file_logging.log", "a+");//fopen("temppp.txt", "a+");
char *log_str = malloc(256);
fseek(f, 0, SEEK_END);
int f_size = ftell(f);
rewind(f);
int num_of_recs=0;
while(fgets(log_str, 256, f)){
num_of_recs++;
}
num_of_recs /= 6;
rewind(f);

struct entry *e = (struct entry *)malloc(num_of_recs*sizeof(struct entry));
//char *log_str = malloc(f_size);
int cc = 0;
int j = 0;
printf("number of entries = %d\n", num_of_recs);
while(fgets(log_str, 256, f)){
cc++;

log_str[strlen(log_str)-1] = '\0';
if(cc % 6 == 1){

(e+j)-> uid = atoi(log_str);

}

if(cc % 6 == 2){
(e+j) -> access_type = atoi(log_str);

}
if(cc % 6 == 3){
(e+j) -> action_denied = atoi(log_str);

}
if(cc % 6 == 4){
strcpy((e+j) -> date, log_str);

}

if(cc % 6 == 5){
strcpy((e+j) -> file, log_str);

}

if(cc % 6 == 0){
strcpy((e+j) -> fingerprint, log_str);


j++;
}


//printf("%s\n", log_str);
}



int i;

int *uids = malloc(num_of_recs*sizeof(int));
//char ***fnames = malloc(num_of_recs*sizeof(char **));
//int *fnumbers = malloc(num_of_recs*sizeof(int));
//int j = 0;
/*
for(i = 0;i<num_of_recs;i++){
fnames[i] = malloc(num_of_recs*sizeof(char*));
for(j = 0;j<num_of_recs;j++){
*(fnames+j)[i] = malloc(num_of_recs*sizeof(char));

}
}
*/
char fnames[30][30][256];
int *fnumbers = malloc(num_of_recs*sizeof(int));
j = 0;

for(i = 0;i<num_of_recs;i++){
if((e+i) -> action_denied == 1){
	//if uid exists in the list already
	if((checkUid(uids, (e+i) -> uid, num_of_recs) == 1)){
		//return the position of this uid in the list
		int pos = retPosOfUid(uids, (e+i) -> uid, num_of_recs);
		
		//if file does not exist in the list
		if(checkfName(fnames[pos], (e+i) -> file, num_of_recs) != 1){
		//add the file in the list
		addfName(fnames[pos], (e+i) -> file, num_of_recs);
		//and increase the number of the different files accesses
		fnumbers[pos] ++ ;
		}else{ //if file exists already, return its position in the list
		/*
			if(retPosOfName(fnames, fnames[i], num_of_recs) != -1){
			int pos = retPosOfName(fnames, fnames[i], num_of_recs);
			fnumbers[pos] ++;

			}else{
			printf("Problem finding the position\n");
			}*/

		}

	//if uid does not exist in the list
	}else{

		//add uid in the list
		addUid(uids, (e+i) -> uid, num_of_recs);

		//find the position of the new uid entry
		int pos = retPosOfUid(uids, (e+i) -> uid, num_of_recs);
		//add the file name in the list of the new uid
		addfName(fnames[pos], (e+i) -> file, num_of_recs);
//printf("Problem finding the position\n");
		fnumbers[pos] = 1 ;

	}



}

}

int nofrecs_mal = 7;
int u = 1;
for(i = 0;i<num_of_recs;i++){

if(fnumbers[i] > nofrecs_mal){
printf("malicious user #%d with uid : %d\n",u, uids[i]);
u++;
}

}



fclose(f);






	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
