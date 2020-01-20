/*
          http://www.unhide-forensics.info/
*/

/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Needed for unistd.h to declare getpgid() and others
#define _XOPEN_SOURCE 500

// Needed for sched.h to declare sched_getaffinity()
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <argp.h>

#include "unhide-output.h"
#include "unhide-linux.h"

typedef enum BOOL_e
{
	FALSE_ = 0,
	TRUE_ = 1
} BOOL_t;


enum CMD_OPT_e
{
	OPT_EMPTY = 1,
	OPT_MORECHECK,
	OPT_ALTSYSINFO,
	OPT_BRUTE,
	OPT_BRUTEDOUBLECHECK,
	OPT_PROC,
	OPT_PROCALL,
	OPT_PROCFS,
	OPT_QUICK,
	OPT_REVERSE,
	OPT_SYS,
	#if UNH_COMPILE_LOW == 1
	OPT_LOW,
	#endif
	OPT_FINAL_END
};

typedef struct arguments
{
	void* empty;
} ARGUMENTS_t;

struct arguments arguments;

const char* argp_program_version = "Unhide 20200120";
const char* argp_program_bug_address = "http://www.unhide-forensics.info";

static char doc[] =
"unhide options:\
\v-";

static char args_doc[] = " ";

// header
const char header[] =
   "Copyright © 2012-2020 Yago Jesus, Patrick Gouin & David Reguera aka Dreg\n"
   "License GPLv3+ : GNU GPL version 3 or later\n"
   "http://www.unhide-forensics.info\n"
   "NOTE : This version of unhide is for systems using Linux >= 2.6 \n"
   "some rootkits detects unhide checking its name. Just copy the original executable with a random name\n"
   "if unhide process crash you can have a rootkit in the system with some bugs\n\n";

static struct argp_option options[] =
{
	{ "verbose", 'v', 0, OPTION_ARG_OPTIONAL, "verbose", 0 },
	{ "morecheck", OPT_MORECHECK, 0, OPTION_ARG_OPTIONAL, "more checks (available only with procfs, checkopendir & checkchdir commands", 0 },
	{ "altsysinfo", OPT_ALTSYSINFO, 0, OPTION_ARG_OPTIONAL, "use alternate sysinfo test in meta-test", 0 },
	{ "logfile", 'l', 0, OPTION_ARG_OPTIONAL, "log result into unhide-linux.log file", 0 },
	{ "brute", OPT_BRUTE, 0, OPTION_ARG_OPTIONAL, "bruteforce the all process IDs", 1 },
	{ "brutedoublecheck", OPT_BRUTEDOUBLECHECK, 0, OPTION_ARG_OPTIONAL, "bruteforce the all process IDs with double check", 1 },
	{ "proc", OPT_PROC, 0, OPTION_ARG_OPTIONAL, "compare /proc with the output of /bin/ps.", 1 },
	{ "procall", OPT_PROCALL, 0, OPTION_ARG_OPTIONAL, "combinates --proc and --procfs", 1 },
	{ "procfs", OPT_PROCFS, 0, OPTION_ARG_OPTIONAL, "compare information gathered from /bin/ps with information gathered by walking in the procfs. With --morecheck option, this test makes more checks", 1 },
	{ "quick", OPT_QUICK, 0, OPTION_ARG_OPTIONAL, "combines the --proc, --procfs and --sys in a quick way. It's about 20 times faster but may give more false positives", 1 },
	{ "reverse", OPT_REVERSE, 0, OPTION_ARG_OPTIONAL, "Verify that all threads seen by ps are also seen in procfs and by system calls", 1 },
	{ "sys", OPT_SYS, 0, OPTION_ARG_OPTIONAL, "compare information gathered from /bin/ps with information gathered from system calls", 1 },
	#if UNH_COMPILE_LOW == 1
	{ "low", OPT_LOW, 0, OPTION_ARG_OPTIONAL, "assembly direct calls vs API calls, this option only works in dynamic form, use unhide-linux-dyn", 1 },
	#endif
	{ NULL, 0, NULL, 0, NULL, 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
	struct arguments* arguments = (struct arguments*) state->input;
	static BOOL_t must = FALSE_;

	switch (key)
	{
	case 'v':
		verbose++;

	case OPT_MORECHECK: 
		morecheck = TRUE;
		break;

	case OPT_ALTSYSINFO:
		RTsys = TRUE;
		break;

	case 'l': 
		logtofile = 1;
		break;

	case OPT_BRUTEDOUBLECHECK:
		must = TRUE_;

		brutesimplecheck = FALSE;
		tab_test[TST_BRUTE].todo = TRUE;
		break;

	case OPT_BRUTE:
		must = TRUE_;

		brutesimplecheck = TRUE;
		tab_test[TST_BRUTE].todo = TRUE;
		break;

	case OPT_PROC:
		must = TRUE_;

		tab_test[TST_PROC].todo = TRUE;
		break;

	case OPT_PROCALL:
		must = TRUE_;

		tab_test[TST_PROC].todo = TRUE;
		tab_test[TST_CHDIR].todo = TRUE;
		tab_test[TST_OPENDIR].todo = TRUE;
		tab_test[TST_READDIR].todo = TRUE;
		break;

	case OPT_PROCFS:
		must = TRUE_;

		tab_test[TST_CHDIR].todo = TRUE;
		tab_test[TST_OPENDIR].todo = TRUE;
		tab_test[TST_READDIR].todo = TRUE;
		break;

	case OPT_QUICK:
		must = TRUE_;

		tab_test[TST_QUICKONLY].todo = TRUE;
		break;

	case OPT_REVERSE:
		must = TRUE_;

		tab_test[TST_REVERSE].todo = TRUE;
		break;

	case OPT_SYS:
		must = TRUE_;

		tab_test[TST_KILL].todo = TRUE;
		tab_test[TST_NOPROCPS].todo = TRUE;
		tab_test[TST_GETPRIO].todo = TRUE;
		tab_test[TST_GETPGID].todo = TRUE;
		tab_test[TST_GETSID].todo = TRUE;
		tab_test[TST_GETAFF].todo = TRUE;
		tab_test[TST_GETPARM].todo = TRUE;
		tab_test[TST_GETSCHED].todo = TRUE;
		tab_test[TST_RR_INT].todo = TRUE;
		break;
		
	#if UNH_COMPILE_LOW == 1
	case OPT_LOW:
		must = TRUE_;
		
		tab_test[TST_LOW].todo = TRUE;
		break;
	#endif

	case ARGP_KEY_END:
		if (!must)
		{
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
		break;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };


// defauly sysctl kernel.pid_max
int maxpid = 32768;

// Threads id for sync
int tid ;

// our own PID
pid_t mypid ;

// options
int verbose = 0;
int morecheck = FALSE;
int RTsys = FALSE;
int brutesimplecheck = TRUE;

// Found hidden proccess flag
int found_HP = 0;

// For logging to file
int logtofile;
FILE *unlog;

// Temporary string for output
char used_options[1000];

// Temporary string for output
char scratch[1000];

// table of test to perform
struct tab_test_t tab_test[MAX_TESTNUM];


/*
 *  Get the maximum number of process on this system. 
 */
void get_max_pid(int* newmaxpid) 
{
   char path[]= "/proc/sys/kernel/pid_max";
   pid_t tmppid = 0;
   FILE* fd= fopen(path,"r");
   if(!fd) 
   {
      warnln(1, unlog, "Cannot read current maximum PID. Using default value %d", * newmaxpid) ;
      return;
   }


   if((fscanf(fd, "%d", &tmppid) != 1) || tmppid < 1) 
   {
      msgln(unlog, 0, "Warning : Cannot get current maximum PID, error parsing %s format. Using default value %d", path, * newmaxpid) ;
      return;
   } 
   else 
   {
      *newmaxpid = tmppid;
   }
   fclose(fd) ;
}

/*
 *  Verify if ps see a given pid. 
 */
int checkps(int tmppid, int checks) 
{

   int ok = 0;
   char pids[30];

   char compare[100];
   char command[60];


   FILE *fich_tmp ;

// printf("in --> checkps\n");   // DEBUG

// The compare string is the same for all test
   sprintf(compare,"%i\n",tmppid);

   if (PS_PROC == (checks & PS_PROC)) 
   {
      sprintf(command,COMMAND,tmppid) ;

      fich_tmp=popen (command, "r") ;
      if (fich_tmp == NULL) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", command, tmppid) ;
         return(0);
      }

      {
         char* tmp_pids = pids;

         if (NULL != fgets(pids, 30, fich_tmp)) 
         {
            pids[29] = 0;

//          printf("pids = %s\n", pids);   // DEBUG
            while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
            {
               tmp_pids++;
            }

            if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
         }
      }

      if (NULL != fich_tmp)
         pclose(fich_tmp);

      if (1 == ok) return(ok) ;   // pid is found, no need to go further
   }

   if (PS_THREAD == (checks & PS_THREAD)) 
   {
      FILE *fich_thread ;

      fich_thread=popen (THREADS, "r") ;
      if (NULL == fich_thread) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", THREADS, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_thread)) && ok == 0) 
      {
         char* tmp_pids = pids;

         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
      }
      if (fich_thread != NULL)
         pclose(fich_thread);

      if (1 == ok) return(ok) ;   // thread is found, no need to go further
   }

   if (PS_MORE == (checks & PS_MORE)) 
   {

      FILE *fich_session ;

      sprintf(command,SESSION,tmppid) ;

      fich_session=popen (command, "r") ;
      if (fich_session == NULL) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", command, tmppid) ;
         return(0);
      }


      while ((NULL != fgets(pids, 30, fich_session)) && ok == 0) 
      {
         char* tmp_pids = pids;

         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) 
         {
            ok = 1;
         }
      }

      pclose(fich_session);

      if (1 == ok) 
         return(ok) ;   // session is found, no need to go further

      FILE *fich_pgid ;

      fich_pgid=popen (PGID, "r") ;
      if (NULL == fich_pgid) 
      {
         warnln(verbose, unlog, "Couldn't run command: %s while ps checking pid %d", PGID, tmppid) ;
         return(0);
      }

      while ((NULL != fgets(pids, 30, fich_pgid)) && ok == 0) 
      {
         char* tmp_pids = pids;

         pids[29] = 0;

         while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
         {
            tmp_pids++;
         }

         if (strncmp(tmp_pids, compare, 30) == 0) 
         {
            ok = 1;
         }
      }

      pclose(fich_pgid);

   }
   return ok;
}

/*
 *  Display hidden process and possibly some information on it. 
 */
void printbadpid (int tmppid) 
{

   int statuscmd ;
   char cmd[100] ;
   struct stat buffer;
   FILE *cmdfile ;
   char cmdcont[1000], fmtstart[128];
   int cmdok = 0, cmdok2 = 0;

   found_HP = 1;
   sprintf(fmtstart,"Found HIDDEN PID: %i", tmppid) ;
   msgln(unlog, 0, "%s", fmtstart) ;

   sprintf(cmd,"/proc/%i/cmdline",tmppid);

   statuscmd = stat(cmd, &buffer);
// statuscmd = 0 ;  // DEBUG

   if (statuscmd == 0) 
   {
      cmdfile=fopen (cmd, "r") ;
      if (cmdfile != NULL) 
      {
         while ((NULL != fgets (cmdcont, 1000, cmdfile)) && 0 == cmdok)
         {
            cmdok++ ;
            msgln(unlog, 0, "\tCmdline: \"%s\"", cmdcont) ;
         }
         fclose(cmdfile);
      }
   }
   if (0 == cmdok) 
   {
      msgln(unlog, 0, "\tCmdline: \"<none>\"") ;
   }
   
   {  // try to readlink the exe
      ssize_t length ;

      sprintf(cmd,"/proc/%i/exe",tmppid);
      statuscmd = lstat(cmd, &buffer);
//    printf("%s",cmd) ; //DEBUG
//      printf("\tstatuscmd : %d\n",statuscmd) ; //DEBUG
      if (statuscmd == 0) 
      {
         length = readlink(cmd, cmdcont, 1000) ;
//         printf("\tLength : %0d\n",(int)length) ; //DEBUG
         if (-1 != length) 
         {
            cmdcont[length] = 0;   // terminate the string
            cmdok++;
            msgln(unlog, 0, "\tExecutable: \"%s\"", cmdcont) ;
         }
         else
         {
            msgln(unlog, 0, "\tExecutable: \"<nonexistant>\"") ;

         }
      }
      else
      {
         msgln(unlog, 0, "\tExecutable: \"<no link>\"") ;
      }
   }
   {       // read internal command name
      sprintf(cmd,"/proc/%i/comm",tmppid);
      statuscmd = stat(cmd, &buffer);
      if (statuscmd == 0) 
      {
         cmdfile=fopen (cmd, "r") ;
         if (cmdfile != NULL) 
         {
//       printf("\tCmdFile : %s\n",cmd) ; //DEBUG
            while ((NULL != fgets (cmdcont, 1000, cmdfile)) && 0 == cmdok2) 
            {
               cmdok2++;
//               printf("\tLastChar : %x\n",cmdcont[strlen(cmdcont)]) ; //DEBUG
               if (cmdcont[strlen(cmdcont)-1] == '\n')
               {
                  cmdcont[strlen(cmdcont)-1] = 0 ;  // get rid of newline
               }
               if (0 == cmdok) // it is a kthreed : add brackets
               {
                  msgln(unlog, 0, "\tCommand: \"[%s]\"", cmdcont) ;
               }
               else
               {
                  msgln(unlog, 0, "\tCommand: \"%s\"", cmdcont) ;
               }
              
            }
            fclose(cmdfile);
         }
         else
         {
            msgln(unlog, 0, "\tCommand: \"can't read file\"") ;
         }
      }
      else 
      {
         msgln(unlog, 0, "\t\"<none>  ... maybe a transitory process\"") ;
      }
   }
   // try to print some useful info about the hidden process
   // does not work well for kernel processes/threads and deamons
   {
      FILE *fich_tmp ;

      sprintf(cmd,"/proc/%i/environ",tmppid);
      statuscmd = stat(cmd, &buffer);
      if (statuscmd == 0) 
      {
         sprintf(cmd,"cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'USER'",tmppid) ;
   //      printf(cmd) ;
         fich_tmp=popen (cmd, "r") ;
         if (fich_tmp == NULL) 
         {
            warnln(verbose, unlog, "\tCouldn't read USER for pid %d", tmppid) ;
         }

         if (NULL != fgets(cmdcont, 30, fich_tmp)) 
         {
            cmdcont[strlen(cmdcont)-1] = 0 ;  // get rid of newline
            msgln(unlog, 0, "\t$%s", cmdcont) ;
         }
         else
         {
            msgln(unlog, 0, "\t$USER=<undefined>", cmdcont) ;
         }
         pclose(fich_tmp);

         sprintf(cmd,"cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'PWD'",tmppid) ;
   //      printf(cmd) ;
         fich_tmp=popen (cmd, "r") ;
         if (fich_tmp == NULL) 
         {
            warnln(verbose, unlog, "\tCouldn't read PWD for pid %d", tmppid) ;
         }

         if (NULL != fgets(cmdcont, 30, fich_tmp)) 
         {
            cmdcont[strlen(cmdcont)-1] = 0 ;  // get rid of newline
            msgln(unlog, 0, "\t$%s", cmdcont) ;
         }
         else
         {
            msgln(unlog, 0, "\t$PWD=<undefined>", cmdcont) ;
         }
         pclose(fich_tmp);

   //      printf("Done !\n");
      }
   }
   printf("\n");
}

int main (int argc, char *argv[]) 
{
	int i = 0;
	
	memset(&arguments, 0, sizeof(arguments));

	printf("%s\n%s", argp_program_version, header);

   if(getuid() != 0){
      die(unlog, "You must be root to run %s !", argv[0]) ;
   }

   // Initialize the table of test to perform.
   // ---------------------------------------
   for (i = 0; i < MAX_TESTNUM; i++) 
   {
      tab_test[i].todo = FALSE;
      tab_test[i].func = NULL;
   }

   tab_test[TST_PROC].func = checkproc;
   tab_test[TST_CHDIR].func = checkchdir;
   tab_test[TST_OPENDIR].func = checkopendir;
   tab_test[TST_READDIR].func = checkreaddir;
   tab_test[TST_GETPRIO].func = checkgetpriority;
   tab_test[TST_GETPGID].func = checkgetpgid;
   tab_test[TST_GETSID].func = checkgetsid;
   tab_test[TST_GETAFF].func = checksched_getaffinity;
   tab_test[TST_GETPARM].func = checksched_getparam;
   tab_test[TST_GETSCHED].func = checksched_getscheduler;
   tab_test[TST_RR_INT].func = checksched_rr_get_interval;
   tab_test[TST_KILL].func = checkkill;
   tab_test[TST_NOPROCPS].func = checkallnoprocps;
   tab_test[TST_BRUTE].func = brute;
   tab_test[TST_REVERSE].func = checkallreverse;
   tab_test[TST_QUICKONLY].func = checkallquick;
   tab_test[TST_SYS_INFO].func = checksysinfo;
   tab_test[TST_SYS_INFO2].func = checksysinfo2;
   tab_test[TST_SYS_INFO3].func = checksysinfo3;
   #if UNH_COMPILE_LOW == 1
   tab_test[TST_LOW].func = checklow;
   #endif 

   argp_parse(&argp, argc, argv, 0, 0, &arguments);

   // get the number max of processes on the system.
   // ---------------------------------------------
   get_max_pid(&maxpid);

   if (logtofile == 1) 
   {
      unlog = init_log(logtofile, header, "unhide-linux") ;
   }

   setpriority(PRIO_PROCESS,0,-20);  /* reduce risk from intermittent processes - may fail, dont care */

   mypid = getpid();

   // Execute required tests.
   // ----------------------
   for (i = 0; i < MAX_TESTNUM; i++) 
   {
      if ((tab_test[i].todo == TRUE) && (tab_test[i].func != NULL))
      {
         tab_test[i].func();
      }
   }

   if (logtofile == 1)
   {
      close_log(unlog, "unhide-linux") ;
   }

   return found_HP;
}
