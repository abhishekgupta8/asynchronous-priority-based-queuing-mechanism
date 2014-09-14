#include "sys_xjob.h"
#include "utils.h"

asmlinkage extern long (*sysptr)(void *arg, int argslen);

/* function for callback mechanism */
static void callback(int pid, char *msg){

	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int msg_size;
	int res;
	UDBG;

	msg_size=strlen(msg);

	skb_out = nlmsg_new(msg_size,0);

	if(!skb_out)
	{
	    printk(KERN_INFO "callback: Failed to allocate new skb\n");
	    return;
	} 

	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);  
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh),msg,msg_size);

	res=nlmsg_unicast(nl_sk,skb_out,pid);

	if(res<0)
   	 	printk(KERN_INFO
		"callback: Error while sending back to user: %d\n", res);
}


int consumer(void *data){

	struct job *job = NULL, *job_mov;
	struct queue *q;
	int err = 0;
	int i, ret = 0, flag = 0;
	char msg[4], *file, id[3];
	mm_segment_t oldfs;
	char algo[8];

start:
	/* waiting on jobs */
	wait_event_interruptible(wqc, q_main_len > 0);
	UDBG;

	/* exiting to kill the thread */
	if(is_exiting > 0)
		goto exit;

	/* grabbing lock */
	mutex_lock(&mutex_len);

	if(q_main_len > 0){
		/* removing job from main queue */
		job = remove_job_priority(q_main);

		if(IS_ERR(job)){
			err = PTR_ERR(job);
			goto out;
		}

		q_main_len--;

		/* moving job from wait to main queue */
		if(q_wait_len > 0){
			printk("sys_xjob.c: Moving job\n");
			job_mov = remove_job(q_wait);
			if(IS_ERR(job_mov)){
				err = PTR_ERR(job_mov);
				goto out;
			}

			q = add_job(q_main, job_mov);
			if(IS_ERR(q)){
				err = PTR_ERR(q);
				add_job(q_wait, job_mov);
				goto out;
			}

			q_main_len++;
			q_wait_len--;
		}
	}

	mutex_unlock(&mutex_len);

	/* waking up producers if any */
	wake_up_all(&wqp);

	/* actually processing the job */
	if(job){
		printk("sys_xjob.c: Executing job\n");	
		
		/* allocating and reseting buffer for calback */
		file = kmalloc(sizeof(char)*500, GFP_KERNEL);
		memset(file, 0, 1000);
		memset(algo, 0, 8);

		msleep(1000);
		for(i=0;i<job->infile_count;i++){
			printk("sys_xjob.c:Infile Name: %s\n", job->infiles[i]);
			
			if(job->job_type == ENCRYPT || 
				job->job_type == DECRYPT){

				/* setting algo */
				if(job->algo == AES)
					strcpy(algo, "aes");
				else if(job->algo == BLOWFISH)
					strcpy(algo, "blowfish");
				
				if(job->file_opt == RENAME)
					flag = 1;
				else
					flag = 0;
			}

			if(job->job_type == CHECKSUM && job->algo == CRC32)
				ret = calc_checksum(job->infiles[i]);
			else if(job->job_type == CHECKSUM && job->algo == MD5)
				ret = hash_md5(job->infiles[i]);
			else if(job->job_type == ENCRYPT){

				ret = encrypt_file(job->infiles[i], 
						flag,
						job->key,
						"ctr", algo);
			}
			else if(job->job_type == DECRYPT){

				ret = decrypt_file(job->infiles[i], 
						flag,
						job->key,
						"ctr", algo);
			}
	
			/* converting error to string */
			sprintf(msg,"%d", ret);
		
			/* preparing file content */
			sprintf(id,"%d", job->job_id);
			strcat(file, id);
			strcat(file, "      ");
			strcat(file, msg);
			strcat(file, "      ");
			strcat(file, job->infiles[i]);	
			strcat(file, "\n");
			schedule();
		}

		callback(job->pid, file);
		oldfs = get_fs();
		set_fs(KERNEL_DS);

		filp->f_op->write(
			filp, file, strlen(file), &filp->f_pos);
					
		set_fs(oldfs);

		/* freeing up the job */
		if(job->key != NULL)
			putname(job->key);
		for(i=0;i<job->infile_count;i++){
			if(!(job->infiles[i] == NULL ))
				putname((job)->infiles[i]);
		}
		kfree(job->infiles);
		kfree(job);
		kfree(file);
		job = NULL;
	}
	schedule();
	goto start;
out:
	mutex_unlock(&mutex_len);
exit:
	return err;
}

asmlinkage long xjob(void *arg, int argslen)
{
	struct job *job = NULL, *job_mov = NULL;
	int error = 0, getname_counter = 0, copy_ret = 0, i = 0; 
	long rem_idx = 0;
	char *file = NULL, **temp;
	void *arguments;
	struct queue_item *t;
	struct queue *q;

	UDBG;
	if(arg == NULL){
		printk("sys_xjob: Passing arguments to kernel space failed\n");
		error = -EINVAL;
		goto final;
	}
		
	/* allocating memory for user arguments */
	arguments = kmalloc(argslen, GFP_KERNEL);
	
	if( arguments == NULL ){
		printk(
		"sys_xjob: Memory allocation for user arguments failed\n");
		error = -ENOMEM;
		goto final;
	}
	
	/* copying arguments from user space and validating for bad addresses */
	copy_ret = copy_from_user(arguments, arg, argslen);
	
	if (copy_ret != 0){
		printk("sys_xjob: Job copy from user space failed\n");
		error = -EFAULT;
		goto free_job;
	}
	job = (struct job*)arguments;

	/*printing jobs */
	if(job->job_type == PRINT){	
		t = q_main->head;
		printk("Job ID   ");
		printk("Job Type        ");
		printk("Infile Count ");
		printk("Infile Name\n");
		printk
		("________________________________________________\n");

		while(t){
			for(i=0; i<t->job->infile_count; i++){	
				printk("%d        ",t->job->job_id);
				if(t->job->job_type == CHECKSUM)
					printk("CHECKSUM        ");
				else if(t->job->job_type == ENCRYPT)
					printk("ENCRYPT         ");
				else if(t->job->job_type == DECRYPT)
					printk("DECRYPT         ");
				printk("%d            ", t->job->infile_count);
				printk("%s\n", t->job->infiles[i]);
			}
			t = t->next;
		}

		t = q_wait->head;
		while(t){
			for(i=0; i<t->job->infile_count; i++){	
				printk("%d        ",t->job->job_id);
				if(t->job->job_type == CHECKSUM)
					printk("CHECKSUM        ");
				else if(t->job->job_type == ENCRYPT)
					printk("ENCRYPT         ");
				else if(t->job->job_type == DECRYPT)
					printk("DECRYPT         ");
				printk("%d            ", t->job->infile_count);
				printk("%s\n", t->job->infiles[i]);
			}
			t = t->next;
		}

		goto free_job;
	}

	/* restricting max number of infiles to 10 */
	if(job->infile_count >10 ){
		printk("sys_xjob: Maximum 10 infiles can be specified\n");
		error = -EPERM;
		goto free_job;
	}

	temp = kmalloc(sizeof(char*)*job->infile_count, GFP_KERNEL);	
	if( temp == NULL ){
		printk(
		"sys_xjob: Memory allocation for infiles failed\n");
		error = -ENOMEM;
		goto free_job;
	}

	job->infiles = temp;

	/* validating key for bad address */	
	if(job->key != NULL){
		file = getname(job->key);
	
		if(IS_ERR(file)){
			printk("sys_xjob: Key cannot be copied\n");
			error = (int) PTR_ERR(file);
			goto free_job_infiles;
		}

		/* overwriting the same structure with kernel address of key */
		job->key = file;
	}

	/* validating infiles for bad address */
	for(i=0;i<job->infile_count;i++){

		file = NULL;
		file = getname(((struct job *)arg)->infiles[i]);
		
		if(IS_ERR(file)){
			printk("sys_xjob: Infile %s name cannot be copied\n",
				((struct job *)arg)->infiles[i]);
			error = (int) PTR_ERR(file);
			goto free_file;
		}
	
	/* overwriting the same structure with kernel address of infile */
	job->infiles[i] = file;	
	
	getname_counter++;
	}

	/* removing job from queue if asked */
	if(job->job_type == REMOVE){	
		
		mutex_lock(&mutex_len);
		for(i=0; i<job->infile_count; i++){
			strict_strtol(job->infiles[i], 0, &rem_idx);
			error = remove_job_idx(q_main, ((int)(rem_idx)));

			if(error == -ENOENT){
				error = remove_job_idx(q_wait,((int)(rem_idx)));
			
				if(error == -ENOENT){
					mutex_unlock(&mutex_len);
					goto free_file;
				}
				else{
					error = 0;
					q_wait_len--;
				}
			}
			else{
			q_main_len--;

			/* moving job from wait to main queue */
			if(q_wait_len > 0){
				printk("sys_xjob.c: Moving job\n");
				job_mov = remove_job(q_wait);
				if(IS_ERR(job_mov)){
					error = PTR_ERR(job_mov);
					mutex_unlock(&mutex_len);
					goto free_file;
				}

				q = add_job(q_main, job_mov);
				if(IS_ERR(q)){
					error = PTR_ERR(q);
					add_job(q_wait, job_mov);
					mutex_unlock(&mutex_len);
					goto free_file;
				}

				q_main_len++;
				q_wait_len--;
			}

			}
		}
		mutex_unlock(&mutex_len);
		goto free_file;
	}

	/* removing all jobs if asked*/
	if(job->job_type == REMOVEALL){	
	
		t = q_main->head;

		mutex_lock(&mutex_len);
		while(t){
			error = remove_job_idx(q_main, t->job->job_id);

			if(error)
				goto free_file;
			else	
				q_main_len--;

			if(t)	
				t = t->next;
		}
		
		t = q_wait->head;

		while(t){
			error = remove_job_idx(q_wait, t->job->job_id);

			if(error)
				goto free_file;
			else	
				q_wait_len--;

			if(t)	
				t = t->next;
		}

		mutex_unlock(&mutex_len);
		goto free_file;
	}

	/* assigning job id */
	job_id++;
	job->job_id = job_id;
	
start:
	mutex_lock(&mutex_len);
	/* adding job to the queue */
	if(q_main_len < MAX_LEN && job){
		printk("sys_xjob: Adding job in main queue\n");
		q = add_job(q_main, job);
		if(IS_ERR(q)){
			error = PTR_ERR(q);
			goto free_file;
		}
		else
			q_main_len++;
	}
	else if(q_wait_len < MAX_LEN && job){
		printk("sys_xjob: Adding job in wait queue\n");
		q = add_job(q_wait, job);
		if(IS_ERR(q)){
			error = PTR_ERR(q);
			goto free_file;
		}
		else
			q_wait_len++;
	}
	else if(q_wait_len == MAX_LEN){
		/* waiting on queue len to decrease */
		printk("sys_xjob: Sleeping producer\n");
		mutex_unlock(&mutex_len);
		wait_event_interruptible(wqp, q_wait_len < MAX_LEN);
		goto start;
	}

	mutex_unlock(&mutex_len);
	/* waking up consumer */
	wake_up_all(&wqc);

	goto final;

free_file:
	if(job->key != NULL)
		putname(job->key);
	for(i=0;i<getname_counter;i++){
		if(!(job->infiles[i] == NULL ))
			putname((job)->infiles[i]);
	}
free_job_infiles:
	kfree(job->infiles);
free_job:
	kfree(job);
final:
	return error;
}

static int __init init_sys_xjob(void)
{
	mm_segment_t oldfs;
	
	UDBG;
	/* initializing main queue */
	q_main = queue_init();
	if(IS_ERR(q_main)){
		printk("sys_xjob: No memory to initialize queue\n");
		return PTR_ERR(q_main);
	}

	/* initializing qait queue */
	q_wait = queue_init();
	if(IS_ERR(q_main)){
		printk("sys_xjob: No memory to initialize queue\n");
		return PTR_ERR(q_wait);
	}
	
	/* initializing wait queues for consumer and producer */
	init_waitqueue_head(&wqp);
	init_waitqueue_head(&wqc);
	
	/* initializing mutex */
	mutex_init(&mutex_len);

	filp = filp_open(".prod_cons.log", O_CREAT | O_TRUNC, 700);

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filp->f_op->write(
		filp,
		"Job Id Status File Name\n", 
		24, &filp->f_pos);
					
	set_fs(oldfs);

	/* initializing consumer threads */
	consumer_thread1 = kthread_create(consumer, NULL, 
				"consumer1");
	wake_up_process(consumer_thread1);

	consumer_thread2 = kthread_create(consumer, NULL, 
				"consumer2");
	wake_up_process(consumer_thread2);

	/* initializing netlink */
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, 
			(void *)callback,NULL,THIS_MODULE);
	if(!nl_sk)
	{
	    printk(KERN_ALERT "Error creating socket.\n");
	    return -ENOMEM;
	}

	printk("installed new sys_xjob module\n");
	if (sysptr == NULL)
		sysptr = xjob;
	return 0;
}

static void  __exit exit_sys_xjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	
	/* deleting queues */
	queue_exit(q_main);
	queue_exit(q_wait);

	/* killing consumer threads */
	q_main_len++;
	is_exiting++;
	wake_up_all(&wqc);

	filp_close(filp, NULL);

	/* destroying netlink */
	netlink_kernel_release(nl_sk);

	printk("removed sys_xjob module\n");
}
module_init(init_sys_xjob);
module_exit(exit_sys_xjob);
MODULE_LICENSE("GPL");