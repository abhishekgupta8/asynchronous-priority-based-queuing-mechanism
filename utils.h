#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>

#define AES_BLOCK_SIZE 16


int hash_md5(char *infile)
{
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct file *filp, *ofilp;
	unsigned char *output, *buf, *final, *outfile, temp[2];
	int i, bytes, pending, cur, err = 0;
	mm_segment_t oldfs;

	output = kmalloc(sizeof(*output)*16, GFP_KERNEL);
	memset(output, 0, strlen(output));
	if (!output)
	{
		err = -ENOMEM;
		goto out;
	}
	final = kmalloc(32, GFP_KERNEL);
	if (!final)
	{
		err = -ENOMEM;
		goto outfree;
	}

	outfile = kmalloc(sizeof(char)*(strlen(infile) + 5), GFP_KERNEL);
	if (!outfile)
	{
		err = -ENOMEM;
		goto finalfree;
	}
	strcpy(outfile, infile);
	strcat(outfile, ".md5");

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open(infile, O_RDONLY, 0);
	ofilp = filp_open(outfile, O_CREAT | O_TRUNC, 666);
	if (!filp || IS_ERR(filp))
		{
		err = PTR_ERR(filp);
		goto outfilefree;
		}
	if (!ofilp || IS_ERR(ofilp))
		{
		err = PTR_ERR(filp);
		goto filpclose;
		}

	pending = filp->f_op->llseek(filp, 0, SEEK_END);
	filp->f_pos = 0;
	memset(output, 0, 16);
	cur = pending > PAGE_SIZE ? PAGE_SIZE: pending;
	buf = kmalloc(cur, GFP_KERNEL);
	if (!buf)
	{
		err = -ENOMEM;
		goto ofilpclose;
	}
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	desc.tfm = tfm;
	desc.flags = 0;
	crypto_hash_init(&desc);

	do{
		pending -= cur;
		bytes = filp->f_op->read(filp, buf, cur, &filp->f_pos);
		sg_init_one(&sg, buf, bytes);
		crypto_hash_update(&desc, &sg, bytes);
	}while(pending > 0);
	crypto_hash_final(&desc, output);
	memset(final, 0, 32);
	for (i=0; i<16; i++)
	{
		sprintf(temp, "%02x", output[i]);
		strcat(final, temp);
	}
	
	bytes = ofilp->f_op->write(ofilp, final, strlen(final), &ofilp->f_pos);
	set_fs(oldfs);
	kfree(buf);
ofilpclose:
	filp_close(ofilp, NULL);
filpclose:
	filp_close(filp, NULL);
outfilefree:
	kfree(outfile);
finalfree:
	kfree(final);
outfree:
	kfree(output);
out:
	return err;

}


u32 calc_checksum(char *infile)
{
	u32 crc = 0;
	char *outfile;
	int pending, bytes, curmax, curpos, err = 0;
	struct file *filp, *ofilp;
	char *buf;
	char mystr[20];
	mm_segment_t oldfs;
	outfile = kmalloc(sizeof(char)*(strlen(infile) + 5), GFP_KERNEL);
	strcpy(outfile, infile);
	strcat(outfile, ".cs");

	filp = filp_open(infile, O_RDONLY, 0);
	ofilp = filp_open(outfile, O_CREAT | O_TRUNC, 666);
	if (!filp || IS_ERR(filp))
		{
		err = PTR_ERR(filp);
		goto out;
		}
	if (!ofilp || IS_ERR(ofilp))
		{
		err = PTR_ERR(filp);
		goto out;
		}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	pending = filp->f_op->llseek(filp, 0, SEEK_END);
	filp->f_pos = 0;
	curmax = PAGE_SIZE;
	crc = crc32(0L, NULL, 0);

	if (pending > PAGE_SIZE)
		buf = kmalloc(curmax, GFP_KERNEL);
	else
		buf = kmalloc(pending, GFP_KERNEL);

	while (pending > curmax)
		{
		curpos = curpos + curmax;	 
		bytes = filp->f_op->read(filp, buf, curmax, &filp->f_pos);
		pending = pending - curmax;
		crc = crc32(crc, buf, curmax);
		}
	bytes = filp->f_op->read(filp, buf, pending, &filp->f_pos);
	crc = crc32(crc, buf, pending);
	sprintf(mystr, "%06u", crc);

	filp->f_op->write(ofilp, mystr, strlen(mystr), &ofilp->f_pos);
	filp_close(filp, NULL);
	filp_close(ofilp, NULL);
	set_fs(oldfs);
	kfree(outfile);	
out:
	return err;
}

int encrypt_inner(const void *key, int key_len, const char *clear_text, 
			char *cipher_text, size_t size, char *encmodealgo)
{
	struct scatterlist sg_in[1], sg_out[1];
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;// = {.tfm = tfm, .flags = 0};
	int rc = 0;

	if(encmodealgo != NULL)
		tfm  = crypto_alloc_blkcipher(encmodealgo, 0, CRYPTO_ALG_ASYNC);
	else{
		rc = -EINVAL;
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	if (IS_ERR(tfm) || !tfm)
		{
		printk("Could not allocate cipher memory\n");
		rc = PTR_ERR(tfm);
		goto out;
		}	
	
	rc = crypto_blkcipher_setkey(tfm, key, key_len);
	if (rc)
		{
		printk("Key could not be set\n");
		goto out;
		}

	sg_init_table(sg_in, 1);
	sg_set_buf(sg_in, clear_text, size);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, cipher_text, size);

	rc = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, size);
	crypto_free_blkcipher(tfm);
	if (rc < 0)
		{
		printk("Encryption failed with %d\n", rc);
		goto out;
		}
	rc = 0;
out:
	return rc;
}

int decrypt_old(const void *key, int key_len, const char *cipher_text, 
			char *clear_text, size_t size, char *encmodealgo)
{
	struct scatterlist sg_in[1], sg_out[1];
	struct crypto_blkcipher *tfm = NULL;
	struct blkcipher_desc desc;	
	int rc = 0;

	if(encmodealgo != NULL){
		tfm  = crypto_alloc_blkcipher(encmodealgo, 0, CRYPTO_ALG_ASYNC);
	}
	else{
		rc = -EINVAL;
		goto out;
	}
	
	desc.tfm = tfm;
	desc.flags = 0;

	if (IS_ERR(tfm) || !tfm)
		{
		printk("Could not allocate cipher memory\n");
		rc = PTR_ERR(tfm);
		goto out;
		}	
	
	rc = crypto_blkcipher_setkey(tfm, key, key_len);
	if (rc)
		{
		printk("Key could not be set\n");
		goto out;
		}

	sg_init_table(sg_in, 1);
	sg_set_buf(sg_in, cipher_text, size);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, clear_text, size);

	rc = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, size);
	crypto_free_blkcipher(tfm);
	if (rc < 0)
		{
		printk("Decryption failed with %d\n", rc);
		goto out;
		}
	rc = 0;
out:
	return rc;
}

static int rename_file(struct file *old, const char *outfile)
{
 	struct file *newfile;
	newfile = filp_open(outfile, O_CREAT | O_WRONLY, 0);
	if (!newfile && IS_ERR(newfile))
	{
		printk("Outfile created with the name delete_file\n");
		return PTR_ERR(newfile);
	}
	lock_rename(old->f_path.dentry->d_parent, 
		newfile->f_path.dentry->d_parent);
	vfs_rename(old->f_path.dentry->d_parent->d_inode,
		old->f_path.dentry,
		newfile->f_path.dentry->d_parent->d_inode,
		newfile->f_path.dentry);
	unlock_rename(old->f_path.dentry->d_parent, 
		newfile->f_path.dentry->d_parent);
	filp_close(newfile, NULL);
	return 0;
}

static int unlink_file(struct file *ofilp)
{
	int err=0;
	struct dentry *dent = ofilp->f_path.dentry;
 	struct inode *ind = dent->d_parent->d_inode;	
	filp_close(ofilp, NULL);
	if(!IS_ERR(dent))
	{	
		mutex_lock_nested(&ind->i_mutex, I_MUTEX_PARENT);
		vfs_unlink(ind, dent);
		mutex_unlock(&ind->i_mutex);
	}
	else
	{
		err = -EBADF;
	}
	return err;
}

int decrypt_file(char *filename, int flag, char *key, char *encmode, char*algo)
{
	int keylen = 16;
	int pending, cur, bytes, err;
	mm_segment_t oldfs = get_fs();
	struct file *filp, *ofilp;
	char *buf;
	char *clear_text;
	char *temp, *encmodealgo;
	set_fs(KERNEL_DS);
	filp = filp_open(filename, O_RDONLY, 666);
	ofilp = filp_open(".tempd", O_CREAT | O_TRUNC, 666);
	if (!filp || IS_ERR(filp))
		{
		printk("Could not read the file %ld\n", PTR_ERR(filp));
		err = PTR_ERR(filp);	
		goto out;
		}
	if (!ofilp || IS_ERR(ofilp))
		{
		printk("Could not open writing file %ld\n", PTR_ERR(ofilp));
		err = PTR_ERR(ofilp);
		goto opfileout;
		}
	pending = filp->f_op->llseek(filp, 0, SEEK_END);
	cur = pending > PAGE_SIZE ? PAGE_SIZE: pending;
	filp->f_pos = 0;
	buf = kmalloc(cur, GFP_KERNEL);
	if (!buf)
		{
		err = -ENOMEM;
		goto bufout;
		}
	clear_text = kmalloc(cur, GFP_KERNEL);
	encmodealgo = kmalloc(strlen(encmode)+strlen(algo)+2, GFP_KERNEL);
	strcpy(encmodealgo, encmode);
	strcat(encmodealgo, "(");
	strcat(encmodealgo, algo);
	strcat(encmodealgo, ")");
	if (!clear_text)
		{
		err = -ENOMEM;
		goto clearout;
		}
	do{
		pending -= cur;
		bytes = filp->f_op->read(filp, buf, cur, &filp->f_pos);
		err = decrypt_old(key, keylen, buf, clear_text, cur, 
							encmodealgo);
		if (err)
			printk("There was an error in decryption %d\n", err);
		bytes = ofilp->f_op->write(ofilp, clear_text, bytes, 
								&ofilp->f_pos);
	}while(pending > 0);
	kfree(encmodealgo);
	set_fs(oldfs);
	
	temp = strstr(filename, ".en");
	if (temp && flag)
		{
		*temp = '\0';
		}
	kfree(clear_text);
	kfree(buf);
	unlink_file(filp);
	rename_file(ofilp, filename);
	filp_close(ofilp, NULL);
	goto out;
clearout:
	kfree(buf);
bufout:
	filp_close(ofilp, NULL);
opfileout:
	filp_close(filp, NULL);
out:
	return err;
}

int encrypt_file(char *filename, int flag, char *key, char *encmode, char*algo)
{
	int keylen = 16, cur=0;	
	int bytes, pending, err = 0;
	char *cipher_text;
	mm_segment_t oldfs = get_fs();
	struct file *filp, *ofilp;
	char *buf, *encmodealgo;

	set_fs(KERNEL_DS);
	filp = filp_open(filename, O_RDONLY, 666);
	if (!filp || IS_ERR(filp))
		{
		printk("Could not read the file %ld\n", PTR_ERR(filp));
		err = PTR_ERR(filp);	
		goto out;
		}
	if (flag)
		strcat(filename, ".en");

	ofilp = filp_open(".tempe", O_CREAT | O_TRUNC, 666);
	if (!ofilp || IS_ERR(ofilp))
		{
		printk("ofilp to write has error\n");
		err = PTR_ERR(ofilp);
		goto opfileout;
		}
	pending = filp->f_op->llseek(filp, 0, SEEK_END);
	cur = pending > PAGE_SIZE ? PAGE_SIZE: pending;
	filp->f_pos = 0;
	buf = kmalloc(cur, GFP_KERNEL);
	if (!buf)
		{
		err = -ENOMEM;
		goto bufout;
		}
	cipher_text = kmalloc(cur, GFP_KERNEL);
	if (!cipher_text)
		{
		err = -ENOMEM;
		goto cipherout;
		}
	encmodealgo = kmalloc(strlen(encmode)+strlen(algo)+2, GFP_KERNEL);
	strcpy(encmodealgo, encmode);
	strcat(encmodealgo, "(");
	strcat(encmodealgo, algo);
	strcat(encmodealgo, ")");
	do{
		pending -= cur;
		bytes = filp->f_op->read(filp, buf, cur, &filp->f_pos);
		memset(cipher_text, 0, cur);
		err = encrypt_inner(key, keylen, buf, cipher_text, cur, 
								encmodealgo);
		if (err)
			printk("There was an error in encryption %d\n", err);
		bytes = ofilp->f_op->write(ofilp, cipher_text, bytes, 
								&ofilp->f_pos);
	}while(pending > 0);
	kfree(encmodealgo);
	unlink_file(filp);
	rename_file(ofilp, filename);
	filp_close(ofilp, NULL);
	set_fs(oldfs);
	kfree(cipher_text);
	kfree(buf);
	goto out;
cipherout:
	kfree(buf);
bufout:
	filp_close(ofilp, NULL);
opfileout:
	filp_close(filp, NULL);
out:
	return err;
}
