/* 
 * tsh - A tiny shell program with job control
 * 
 * github:huangrt01   THU EE 
 * 
 * -------------------------
 * parallel commands
 * -------------------------
 * 
 */
#include "csapp.c"

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */
#define MAXPATH      64
#define MAXPARALLEL   8    /* max parallel commands */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z         -- SIGTSTP sent to each process in the foreground job
 *     FG -> XX  : ctrl-c         -- SIGINT sent to each process in the foreground job 
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */
char *paths[MAXPATH] = {"/bin", NULL};    /* max path number */

struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
volatile sig_atomic_t fg_pid;
/* End global variables */

struct function_args
{
    pthread_t thread;
    char **argv;
    int argc;
    FILE* out;
    sigset_t prev_mask;
};

/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv, int argc);
void executable(char **argv, int argc, char *cmdline, FILE *OUT, int bg);
void do_bgfg(char **argv, int argc);
void waitfg(pid_t pid,sigset_t prev_mask);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv, int *argc); 
void redirect(FILE *out);
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs); 
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid); 
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid); 
int pid2jid(pid_t pid); 
void listjobs(struct job_t *jobs);

void usage(void);


/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv) 
{
    char c;
    int emit_prompt = 1; /* emit prompt (default) */
    int batch_mode = 0; /* batch mode */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    /* 1 represents stdout, 2 represents stderr*/
    Dup2(STDOUT_FILENO,STDERR_FILENO);
    //dup2(1, 2);
    FILE *IN = stdin;
    char **input_file;

    /* Parse the command line */
    while ((c = getopt(argc, argv, "b:hvp")) != EOF) {
        switch (c) {
            case 'b':             /* batch mode */
                batch_mode = 1;
                emit_prompt = 0;
                readtoMem(&input_file, optarg,MAXLINE);
                break;
            case 'h':             /* print help message */
                usage();
                break;
            case 'v':             /* emit additional diagnostic info */
                verbose = 1;
                break;
            case 'p':             /* don't print a prompt */
                emit_prompt = 0;  /* handy for automatic testing */
                break;
            default:
                usage();
        }
    }
    if(argc-optind>0)       /* wrong shell input*/
        usage();


    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT,  sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler); 

    /* Initialize the job list */
    initjobs(jobs);
    char *cmdline; 
    /* Execute the shell's read/eval loop */
    while(1){
        cmdline = (char *)Malloc(MAXLINE);
        /* Read command line */
        if (emit_prompt) {
            printf("%s", prompt);
            fflush(stdout);
        }
        if(!batch_mode){ 
            Fgets(cmdline, MAXLINE, IN);
            if (ferror(IN) || feof(IN)) /* feof(IN): End of file (ctrl-d) */
                break;
        }
        else{
            if(!*input_file) break;
            strcpy(cmdline,*input_file);
            input_file++;
            // char *temp = *input_file;
            // input_file++;
            // free(temp);
        }    
        if(verbose && batch_mode ) printf("Evaluating cmdline:%s\n",cmdline);

        /* Evaluate the command line */
        /* implement the parallel commands: 
            the first n-1 processes are in bg and the last one is in fg */
        /* to wait the parallel background processes, use the syscall wait() in shell */ 
        char *token;
        char delim_parallel[]="&";
        char parallel_command[MAXPARALLEL][MAXLINE];
        int parallel_num=0;
        for(token = strsep(&cmdline,delim_parallel);token != NULL; token = strsep(&cmdline,delim_parallel)){
            strcpy(parallel_command[parallel_num],token);
            parallel_num++;
        }
        for(int i=0;i<parallel_num;i++){
            token = parallel_command[i];
            if (strlen(token) > 1)
            {
                if (token[strlen(token) - 1] != '\n')
                {
                    strcat(token,"\n");
                }
                if (i != parallel_num - 1)  // there must be one fg job!
                {
                    token[strlen(token) - 1] = '\0';
                    strcat(token, " &\n");
                }
            }
            if (strlen(token))
                eval(token);
        }
        free(cmdline);
        fflush(stdout);
        fflush(stdout);
    } 

    fflush(stdout);
    Fclose(IN);
    exit(0); 
}
  
/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
*/
void eval(char *cmdline) 
{
    char *argv[MAXARGS];  //Argument list execve()
    int argc;
    char buf[MAXLINE];   //Holds modified command line
    int bg;               //Should the job run in bg or fg?
    FILE *OUT=stdout;            //Output file

    strcpy(buf,cmdline);
    bg=parseline(buf,argv,&argc);
    if(argv[0]==NULL)
        return; //Ignore empty lines
    if(argc>=3){
        if(!strcmp(argv[argc-2],">")){
            OUT = Fopen(argv[argc-1],"w");
            argc-=2;
            argv[argc]=NULL;
        }
        else if(!strcmp(argv[argc-2],">>")){
            OUT = Fopen(argv[argc-1],"a");
            argc-=2;
            argv[argc]=NULL;
        }
    }
    if(!builtin_cmd(argv,argc)){ //pathname of an execuatble file
        executable(argv,argc,cmdline,OUT,bg);
    }
    return;
}

/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv, int *argc) 
{
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
	    buf++;

    /* Build the argv list */
    *argc = 0;
    if (*buf == '\'') {
        buf++;
        delim = strchr(buf, '\'');
    }
    else {
        delim = strchr(buf, ' ');
        char *delim_tab = strchr(buf, '\t');
        if (delim && delim_tab)
            delim = (delim < delim_tab) ? delim : delim_tab;
        else if (delim_tab)
            delim = delim_tab;
    }

    while (delim) {
        argv[(*argc)++] = buf;
        *delim = '\0';
        buf = delim + 1;
        while (*buf && ((*buf == ' ')||(*buf == '\t'))) /* ignore spaces and tabs */
            buf++;

        if (*buf == '\'') {
            buf++;
            delim = strchr(buf, '\'');
        }
        else {
            delim = strchr(buf, ' ');
            char *delim_tab = strchr(buf, '\t');
            if (delim && delim_tab)
                delim = (delim < delim_tab) ? delim : delim_tab;
            else if (delim_tab)
                delim = delim_tab;
        }
    }
    argv[*argc] = NULL;
    
    if (argc == 0)  /* ignore blank line */
	    return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[*argc-1] == '&')) != 0) {
	    argv[--(*argc)] = NULL;
    }
    return bg;
}

/*
 * searchpath - search file in the paths
 * 
 * 
 */
int searchpath(char **file){
    int i=0;
    char path[MAXLINE];
    while(paths[i]){
        snprintf(path,MAXLINE,"%s/%s",paths[i],*file);
        if(access(path,X_OK)==0){
            *file = (char *)Malloc(MAXLINE);
            strcpy(*file,path);
            return 0;
        }
        i++;
    }
    return -1;
}



/*
 * redirect - redirect the output from STDOUT to FILE * OUT
 * 
 */
void redirect(FILE *out){
    int outFileNo;
    if((outFileNo = fileno(out)) == -1){
        printf("redirection failed\n");
        fflush(stdout);
        return;
    }
    if(outFileNo != STDOUT_FILENO){
        Dup2(outFileNo, STDOUT_FILENO);
        Dup2(outFileNo, STDERR_FILENO);
        Fclose(out);
    }
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 */
int builtin_cmd(char **argv, int argc) 
{
    if(!strcmp(argv[0],"quit")||!strcmp(argv[0],"exit"))     //quit and exit command
        exit(0);
    else if(!strcmp(argv[0],"cd")){
        if(argc==2){
            Chdir(argv[1]);
        }
        else
            printf("cd command requires 1 argument\n");
    }
    else if(!strcmp(argv[0],"pwd")){
        if(argc==1){
            char temp[MAXLINE];
            Getcwd(temp,MAXLINE);
            printf("%s\n",temp);
        }
        else
            printf("pwd command requires no argument\n");
    }
    else if(!strcmp(argv[0],"&"))        //ignore Singleton &
        return 1;
    else if(!strcmp(argv[0],"jobs")){
        listjobs(jobs);
    }
    else if(!strcmp(argv[0],"bg")||!strcmp(argv[0],"fg")){
        do_bgfg(argv,argc);
    }
    else if(!strcmp(argv[0],"path")){
        paths[0]=NULL;
        size_t i;
        for(i=0;i<argc-1;i++){
            paths[i]=strdup(argv[i+1]);
        }
        paths[i+1]=NULL;
    }
    else if(!searchpath(&argv[0]))
        return 0;
    else
        return 0;     /* not a builtin command */
    fflush(stdout);
    return 1;
}

/*
 *
 * executable - run the executable file
 * 
 */
void executable(char **argv,int argc, char *cmdline, FILE *OUT, int bg){

//实现parallel的思路：
    pid_t pid; //Process id

    sigset_t mask_chld, prev_mask, mask_all;
    Sigemptyset(&mask_chld);
    Sigaddset(&mask_chld, SIGCHLD);
    Sigfillset(&mask_all);

    /* Block SIGCHLD to prevent the race condition where the child is reaped by sigchld handler
            (and thus removed from the job list) before the parent calls addjob. */
    Sigprocmask(SIG_BLOCK, &mask_chld, &prev_mask);

    //TODO: 改成Pthread_create
    pid = Fork();
    if (pid == 0) //child runs user job
    {

        //restore the prev_mask
        Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
        //puts the child in a new process group whose group ID is identical to the child’s PID
        setpgid(0, 0);
        //redirection
        redirect(OUT);
        //run the job
        Execve(argv[0], argv, environ);
        //这个要加，防止execve失败
        exit(0);
    }

    //before manipulating the global variables, mask all the possible signals
    Sigprocmask(SIG_BLOCK, &mask_all, NULL);

    //TODO: pid改成pid数组
    // waitfg同时wait多个，可以顺序wait
    addjob(jobs, pid, bg + 1, cmdline);
    if (!bg)
    {
        waitfg(pid, prev_mask);      
    }
    else
    {
        printf("[%d] (%d) %s", pid2jid(pid), pid, cmdline);
        // 这行是否需要换行？如果加\n，输出多了一行；如果不加，神奇地符合要求，prompt自动换行了，不知道这是为什么?
        fflush(stdout);
    }
    /* Restore previous blocked set, unblocking SIGCHLD */
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
} 


/* 
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv, int argc) 
{
    if (argc != 2)
    {
        printf("%s command requires PID or %%jobid argument\n", argv[0]);
        fflush(stdout);
        return;
    }
    
    int cur_jid=0;
    pid_t cur_pid=0;
    struct job_t *cur_job;
    char *para=argv[1];

    sigset_t prev_mask, mask_all;
    Sigfillset(&mask_all);

    if(para[0]=='%'){
        // input is jid
        cur_jid=atoi(&para[1]);
        if(!cur_jid){
            printf("%s: argument must be a PID or %%jobid\n", argv[0]);
            fflush(stdout);
            return;
        }
        
    }
    else{
        // input is pid
        cur_pid=atoi(para);
        if(!cur_pid){
            printf("%s: argument must be a PID or %%jobid\n", argv[0]);
            fflush(stdout);
            return;
        }
        
    }

    Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    if(cur_pid)
        cur_jid=pid2jid(cur_pid);
    cur_job = getjobjid(jobs, cur_jid);

    if (cur_job == NULL)
    {
        if(cur_pid)
            printf("(%d): No such process\n", cur_pid);
        else
            printf("%%%d: No such job\n", cur_jid);
        fflush(stdout);
        Sigprocmask(SIG_SETMASK,&prev_mask,NULL);
        //回复sigmask状态不能省
        return;
    }


    if(!strcmp(argv[0],"bg")){ // bg command
        switch (cur_job->state)
        {
        case ST:
            cur_job->state = BG;
            kill(-(cur_job->pid), SIGCONT);
            printf("[%d] (%d) %s", cur_job->jid, cur_job->pid, cur_job->cmdline);
            break;
        case BG:
            break;
        case UNDEF:
        case FG:
            unix_error("bg command error: UNDEF or FG process");
        }
    }
    else{ // fg command
        switch (cur_job->state)
        {
        case ST:
            cur_job->state = FG;
            kill(-(cur_job->pid), SIGCONT);
            waitfg(cur_job->pid,prev_mask);
            break;
        case BG:
            cur_job->state = FG;
            waitfg(cur_job->pid,prev_mask);
            break;
        case FG:
        case UNDEF:
            unix_error("FG command error: UNDEF or FG process");
        }
    }
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    return;
}

/* 
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid,sigset_t prev_mask)
{
    fg_pid=pid;
    //spin loop
    while(fg_pid){
        Sigsuspend(&prev_mask);
        //more efficient than sleep
    }
    if(verbose){
        Sio_puts("waitfg: Process (");
        Sio_putl(pid);
        Sio_puts(") no longer the fg process\n");
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig) 
{
    int old_errno=errno;
    errno = 0;
    pid_t pid;
    int status;
    if (verbose)
        Sio_puts("sigchld_handler: entering\n");

    sigset_t prev_mask, mask_all;
    Sigfillset(&mask_all);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED))>0){    //Reap a zombie child
        Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
        struct job_t *cur_job = getjobpid(jobs, pid);
        int cur_jid=pid2jid(pid);
        if(fg_pid==pid) fg_pid=0;
        if (WIFSTOPPED(status))
        {
            cur_job->state=ST;
            Sio_puts("Job ["); Sio_putl(cur_jid); Sio_puts("] (");
            Sio_putl(pid); Sio_puts(") stopped by signal "); 
            Sio_putl(WSTOPSIG(status)); Sio_puts("\n");
        }
        else{
            if (verbose){
                Sio_puts("sigchld_handler: "); Sio_puts("Job [");
                Sio_putl(cur_job->jid); Sio_puts("] (");
                Sio_putl(cur_job->pid); Sio_puts(") deleted\n");
                if(WIFEXITED(status)){
                    Sio_puts("sigchld_handler: "); Sio_puts("Job [");
                    Sio_putl(cur_job->jid); Sio_puts("] (");
                    Sio_putl(cur_job->pid); Sio_puts(") terminates OK (status ");
                    Sio_putl(WTERMSIG(status)); Sio_puts(")\n");
                }
            }
            if (WIFSIGNALED(status))
            { //进程异常终止
                Sio_puts("Job ["); Sio_putl(cur_jid); Sio_puts("] (");
                Sio_putl(pid); Sio_puts(") terminated by signal "); 
                Sio_putl(WTERMSIG(status)); Sio_puts("\n");
            }
            deletejob(jobs,pid);
        }

        Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    

    // at this time, error can be EINTR / success
    if(errno!=ECHILD && errno!=EINTR && errno != 0)
        unix_error("waitpid error"); //Sio
    
    if(verbose)
        Sio_puts("sigchld_handler: exiting\n");
    errno = old_errno;
    return;
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig) 
{
    int old_errno=errno;

    //forward it to the process group that contains the foreground job
    pid_t gpid ;

    if (verbose)
        Sio_puts("sigint_handler: entering\n");

    //Protect accesses to shared global data structures by blocking all signals
    sigset_t mask_all, prev_mask;
    Sigfillset(&mask_all);
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    if ((gpid = fgpid(jobs))){
        struct job_t *cur_job = getjobpid(jobs, gpid);
        if(verbose){
            Sio_puts("sigint_handler: Job [");
            Sio_putl(cur_job->jid);
            Sio_puts("] (");
            Sio_putl(cur_job->pid);
            Sio_puts(") killed\n");
        }
        kill(-gpid, SIGINT);
    }
        
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL);

    if (verbose)
        Sio_puts("sigint_handler: exiting\n");

    errno=old_errno;
    return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig) 
{
    int old_errno=errno;

    //forward it to the process group that contains the foreground job
    pid_t gpid;

    if (verbose)
        Sio_puts("sigtstp_handler: entering\n");

    //Protect accesses to shared global data structures by blocking all signals
    sigset_t mask_all, prev_mask;
    Sigfillset(&mask_all);
    Sigprocmask(SIG_BLOCK, &mask_all, &prev_mask);
    if((gpid = fgpid(jobs))){
        struct job_t *cur_job = getjobpid(jobs, gpid);
        if(verbose){
            Sio_puts("sigtstp_handler: Job [");
            Sio_putl(cur_job->jid);
            Sio_puts("] (");
            Sio_putl(cur_job->pid);
            Sio_puts(") stopped\n");
        }
        kill(-gpid, SIGTSTP);
    }
        
    Sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    if (verbose)
        Sio_puts("sigtstp_handler: exiting\n");
    errno=old_errno;
    return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	    clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) 
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].jid > max)
	    max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) 
{
    int i;
    
    if (pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == 0) {
            jobs[i].pid = pid;
            jobs[i].state = state;
            jobs[i].jid = nextjid++;
            if (nextjid > MAXJOBS)
                nextjid = 1;
            strcpy(jobs[i].cmdline, cmdline);
            if(verbose){
                printf("Added job [%d] %d %s\n\r", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            fflush(stdout); // 这句如果不加，会影响对shell进程的理解
            return 1;
        }
    }
    printf("Tried to create too many jobs\n\r");
    fflush(stdout);
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) 
{
    int i;

    if (pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
        if (jobs[i].pid == pid) {
            clearjob(&jobs[i]);
            nextjid = maxjid(jobs)+1;
            return 1;
        }
    }
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].state == FG)
            return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
	    return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].pid == pid)
            return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) 
{
    int i;

    if (jid < 1)
	    return NULL;
    for (i = 0; i < MAXJOBS; i++)
        if (jobs[i].jid == jid)
            return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) 
{
    int i;

    if (pid < 1)
	    return 0;
    for (i = 0; i < MAXJOBS; i++)
    if (jobs[i].pid == pid) {
        return jobs[i].jid;
    }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) 
{
    int i;
    
    for (i = 0; i < MAXJOBS; i++) {
    if (jobs[i].pid != 0) {
        printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
        switch (jobs[i].state) {
        case BG: 
            printf("Running ");
            break;
        case FG: 
            printf("Foreground ");
            break;
        case ST: 
            printf("Stopped ");
            break;
        default:
            printf("listjobs: Internal error: job[%d].state=%d ", 
            i, jobs[i].state);
        }
        printf("%s", jobs[i].cmdline);
    }
    }
    fflush(stdout);
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) 
{
    printf("Usage: shell [-bhvp]\n");
    printf("   -b   batch mode, -b batch_file\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 *   ctrl-\ => SIGQUIT
 */
void sigquit_handler(int sig)  
{
    printf("Terminating after receipt of SIGQUIT signal\n\r");
    fflush(stdout);
    exit(1);
}




