#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#define __NR_xjob	349	/* our private syscall number */

/* types of operationss */
#define CHECKSUM 1
#define ENCRYPT 2
#define DECRYPT 3
#define PRINT 4
#define REMOVE 5
#define RENAME 6
#define OVERWRITE 7
#define REMOVEALL 8

#define NETLINK_USER 31

/* types of algorithms */
#define AES 1
#define BLOWFISH 2

/* checksum algo */
#define MD5 1
#define CRC32 2

#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct sockaddr_nl src_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

struct job{
	int job_type;
	int job_id;
	int infile_count;
	pid_t pid;
	int file_opt;
	int priority;
	int algo;
	char **infiles;
	char *key;
};

struct job *task;

int netlink_rcv()
{
	sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(sock_fd<0)
		return -1;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid(); /* self pid */

	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Read message from kernel */
	recvmsg(sock_fd, &msg, 0);
	printf("Job Id Status File Name\n");
	printf("%s\n", (char *)NLMSG_DATA(nlh));
	close(sock_fd);
}

int main(int argc, char *argv[])
{

	int argslen, rc, option, i;
	int callback = 0;
	struct sigaction action;

	/* checking for missing arguments */
	if( argc < 2 )
	{
		rc=-EINVAL;
		errno=EINVAL;
		printf(
	"Correct Syntax:./xhw3 job_type infile1 infile2...\n");
		goto out;
	}
	
	task = malloc(sizeof(struct job));
	if(task == NULL){
		rc= -ENOMEM;
		errno= ENOMEM;
		goto out;
	}
	
	task->job_type = 0;
	task->file_opt = 0;	
	task->priority = 0;
	task->algo = 0;
	
	/* getting all arguments */
	while( ( option = getopt( argc, argv, "csprAEDORe:a:" ) ) != -1 )
	{	
 		switch(option)
		{	
		
			case 'c' : 
			callback = 1;
			break;
				
			case 's' : 
			if(task->job_type != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->job_type = CHECKSUM;
			break;

			case 'D' : 
			if(task->job_type != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->job_type = DECRYPT;
			break;

			case 'E' : 
			if(task->job_type != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->job_type = ENCRYPT;
			break;

			case 'p' : 
			if(task->job_type != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->job_type = PRINT;
			break;

			case 'r' : 
			if(task->job_type != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->job_type = REMOVE;
			break;

			case 'A' : 
			if(task->job_type != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->job_type = REMOVEALL;
			break;

			case 'O' : 
			if(task->file_opt != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->file_opt = OVERWRITE;
			break;

			case 'R' : 
			if(task->file_opt != 0){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->file_opt = RENAME;
			break;		

			case 'e' : 
			if((task->priority != 0) ||
				atoi(optarg) > 3 ||
				atoi(optarg) < 1){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->priority = atoi(optarg);
			break;		

			case 'a' : 
			if((task->job_type != ENCRYPT &&
				task->job_type != DECRYPT &&
				task->job_type != CHECKSUM &&
				task->job_type != 0) ||
				atoi(optarg) > 2 ||
				atoi(optarg) < 1){
				rc=-EINVAL;
				errno=EINVAL;
				goto out_free;
			}
			task->algo = atoi(optarg);
			break;		

			case '?' :
			rc=-EINVAL;
			errno=EINVAL;
			perror("Error: Wrong flag(s) entered\nError");
			goto out_free;

		}

	}

	/* checking for missing files */
	if ((argc - optind < 1) && 
		(task->job_type != PRINT && task->job_type != REMOVEALL))
	{
		rc = -EINVAL;
		errno = EINVAL;
		printf("Error: Input filename(s) missing\n");
		goto out_free;
	}
	
	if(task->job_type == 0)
		task->job_type = CHECKSUM;

	if(task->file_opt == 0)
		task->file_opt = RENAME;

	if(task->priority == 0)
		task->priority = 3;

	if(task->algo == 0)
		task->algo = AES;

	if(task->job_type != PRINT){

		if(task->job_type == ENCRYPT || task->job_type == DECRYPT){	
			/* calculating nmuber of input files */
			if(argc-optind-1 != 0){
				/* setting key */
				task->key =  argv[argc-1];
				task->infile_count = argc-optind-1;
			}
			else{
				task->infile_count = argc-optind;
				task->key = malloc(sizeof(char)*5);
				strcat(task->key, "00000");
			}

		}
		else
			task->infile_count = argc-optind;

		/* setting infiles */
		task->infiles=malloc(sizeof(char*)*task->infile_count);
	
		for(i=0;i<task->infile_count;i++)
		{
			task->infiles[i]=argv[optind+i];
		}
	}

	/* setting pid */
	task->pid = getpid();

	void *dummy = task; 
	argslen = sizeof(*task);

	/* system call */
  	rc = syscall(__NR_xjob, dummy, argslen);
	
	/* waiting for callback */
	if (task->job_type != PRINT && 
		task->job_type != REMOVEALL &&
		task->job_type != REMOVE &&
		callback ==1){
		netlink_rcv();	
	}

out_free:
	/* deallocating memory */
	if(task->infiles)
		free(task->infiles);

out:	
	/* printing appropriate message */
	if (rc >= 0){
		printf("%d\n", rc);
	}
	else{
		printf("Error Number: %d\n", errno);
		perror("Error");
	}

	exit(rc);
}
