#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/buffer_head.h>
#include <linux/crc32.h>
#include <linux/sched.h>
#include <asm/siginfo.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 31
#define MAX_LEN 5

/* types of operationss */
#define CHECKSUM 1
#define ENCRYPT 2
#define DECRYPT 3
#define PRINT 4
#define REMOVE 5
#define RENAME 6
#define OVERWRITE 7
#define REMOVEALL 8

/* types of algorithms */
#define AES 1
#define BLOWFISH 2

/* checksum algo */
#define MD5 1
#define CRC32 2

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/*  main queue and wait queue */
struct queue *q_main;
struct queue *q_wait;

/* length for main and wait queue */
int q_main_len = 0;
int q_wait_len = 0;

/* lock for producer and consumer */
struct mutex mutex_len;

/* wait queues for consumer and producer */
wait_queue_head_t wqp, wqc;

/* flag for exiting threads */
int is_exiting = 0;

/* unique job ids */
int job_id = 0;

/* consumer threads */
struct task_struct *consumer_thread1;
struct task_struct *consumer_thread2;

/* socket */
struct sock *nl_sk = NULL;

struct file *filp;

/* job structure */
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

/* structure for queue elements */
struct queue_item{
	struct job *job;
	struct queue_item *next;
};

/* struct queue head */
struct queue{
	struct queue_item *head;
	struct queue_item *tail;
	struct mutex mutex_queue;
};

/* function to initialize queue */
struct queue *queue_init(void){
	
	struct queue *q = kmalloc(sizeof(struct queue*), GFP_KERNEL);
	UDBG;	
	if(q == NULL){
		printk("sys_xjob.h: cannot initialize the queue\n");
		return ERR_PTR(-ENOMEM);
	}
	else{
		q->head = NULL;
		q->tail = NULL;
	}
	
	mutex_init(&q->mutex_queue);
	return q;
}

/* function to add a job to a queue */
struct queue *add_job(struct queue *q, struct job *j){
	
	int err = 0;
	struct queue_item *qt;
	UDBG;

	printk("add job: job_id: %d\n", j->job_id);

	/* checking if queue is initialized or not */
	if(q == NULL){
		err = -EINVAL;
		printk("sys_xjob.h: queue not initialized:err %d\n", err);
		goto out;
	}

	qt = kmalloc(sizeof(struct queue_item*), GFP_KERNEL);
	
	if(qt == NULL){
		err = -ENOMEM;
		printk("sys_xjob.h: cannot add job to the queue:err %d\n", err);
		goto out;
	}

	qt->job = j;
	qt->next = NULL;

	mutex_lock(&q->mutex_queue);
		if(q->head == NULL && q-> tail == NULL){
			/* adding first element */
			q->head = qt;
			q->tail = qt;
		}
		else{
			/* adding at the tail */
			q->tail->next = qt;
			q->tail = qt;
		}
	mutex_unlock(&q->mutex_queue);

out:
	if(err != 0)
		return ERR_PTR(err);
	else 
		return q;
}

/* function to remove a job from a queue */
struct job *remove_job(struct queue *q){

	int err = 0;
	struct job *job;
	struct queue_item *first_element = NULL, *second_element = NULL;
	UDBG;
	/* checking if queue is initialized or not */
	if(q == NULL){
		err = -EINVAL;
		printk("sys_xjob.h: queue not initialized:err %d\n", err);
		goto out;
	}
	
	if(q->head == NULL && q->tail == NULL){
		/* queue is empty */
		job = NULL;
		err = -EINVAL;
		goto out;	
	}
	
	mutex_lock(&q->mutex_queue);
	first_element = q->head;
	second_element = q->head->next;
	q->head = second_element;

	/* check if queue got empty */
	if(q->head == NULL)
		q->tail = NULL;
	mutex_unlock(&q->mutex_queue);

	job = first_element->job;
	kfree(first_element);

out:
	if(err != 0)
		return ERR_PTR(err);
	else 
		return job;
}

/* function to remove a job from a queue with job_id*/
int remove_job_idx(struct queue *q, int job_id){

	int err = 0, found = 0, i;
	struct queue_item *first_element = NULL, *second_element = NULL;
	UDBG;
	/* checking if queue is initialized or not */
	if(q == NULL){
		err = -EINVAL;
		printk("sys_xjob.h: queue not initialized:err %d\n", err);
		goto out;
	}
	
	if(q->head == NULL && q->tail == NULL){
		/* queue is empty */
		err = -EINVAL;
		goto out;	
	}
	
	mutex_lock(&q->mutex_queue);
	first_element = q->head;
	second_element = NULL;

	while(first_element != NULL){
		if(first_element->job->job_id == job_id){
			if(first_element == q->head){
				q->head = first_element->next;
			}
			else{
				second_element->next = first_element->next;
				if(!first_element->next){
					q->tail = second_element;
				}
			}
			found++;
			break;
		}
		second_element = first_element;
		if(first_element)
			first_element = first_element->next;
	}

	/* check if queue got empty */
	if(q->head == NULL)
		q->tail = NULL;
	mutex_unlock(&q->mutex_queue);
	if(found != 0){
		/* freeing up element */
		if(first_element->job->key != NULL)
			putname(first_element->job->key);
		for(i=0;i<first_element->job->infile_count;i++){
			if(!(first_element->job->infiles[i] == NULL ))
				putname(first_element->job->infiles[i]);
		}
		kfree(first_element->job->infiles);
		kfree(first_element->job);
		kfree(first_element);
	}
	else{
		err= -ENOENT;
	}

out:
	return err;
}

/* function to remove a job from a queue with job_id*/
struct job *remove_job_priority(struct queue *q){

	int err = 0, i= 1;
	struct job *job;
	struct queue_item *first_element = NULL, *second_element = NULL;
	UDBG;
	/* checking if queue is initialized or not */
	if(q == NULL){
		err = -EINVAL;
		printk("sys_xjob.h: queue not initialized:err %d\n", err);
		goto out;
	}
	
	if(q->head == NULL && q->tail == NULL){
		/* queue is empty */
		err = -EINVAL;
		goto out;	
	}
	
	mutex_lock(&q->mutex_queue);
	for(i=1; i<4; i++){
		first_element = q->head;
		second_element = NULL;
		while(first_element != NULL){
			if(first_element->job->priority == i){
				if(first_element == q->head){
					q->head = first_element->next;
				}
				else{
					second_element->next = 
						first_element->next;

					if(!first_element->next){
						q->tail = second_element;
					}
				}
				goto found;
			}
			second_element = first_element;
			if(first_element)
				first_element = first_element->next;
		}
	}
found:
	/* check if queue got empty */
	if(q->head == NULL)
		q->tail = NULL;
	mutex_unlock(&q->mutex_queue);
	job = first_element->job;
	kfree(first_element);

out:
	if(err != 0)
		return ERR_PTR(err);
	else 
		return job;
}

/* function to remove a queue */
void queue_exit(struct queue *q){
	struct job *job;
	struct queue_item *t;
	int i = 0;
	UDBG;
	t = q->head;
	while(t){
		job = remove_job(q);
		if(job->key != NULL)
			putname(job->key);
		for(i=0;i<job->infile_count;i++){
			if(!(job->infiles[i] == NULL ))
				putname((job)->infiles[i]);
		}
		kfree(job->infiles);
		kfree(job);
		if (t)
			t = t->next;
	}

	kfree(q);
}
