/*
          http://www.unhide-forensics.info
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

#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "unhide-output.h"
#include "unhide-tcp.h"

const char* argp_program_version = "unhide-tcp 20200101";
const char* argp_program_bug_address = "http://www.unhide-forensics.info";

static char doc[] =
"unhide-tcp options:\
\v-";

static char args_doc[] = " ";

// header
const char header[] =
       "Copyright © 2012-2020 Yago Jesus, Patrick Gouin & David Reguera aka Dreg\n"
       "License GPLv3+ : GNU GPL version 3 or later\n"
       "http://www.unhide-forensics.info\n"
       "NOTE : some rootkits detects unhide checking its name. Just copy the original executable with a random name\n"
       "if unhide process crash you can have a rootkit in the system with some bugs\n\n";

// options
int verbose = 0;
int use_fuser = 0;
int use_lsof = 0;
int use_ss = 1;   // use ss by default
int use_quick = 0;

char checker[10] = "ss" ;

// Temporary string for output
char scratch[1000];

// For logging to file
int logtofile = 0;
FILE *unlog;

// Global hidden port counter, used only to set the exit code of the program
int hidden_found;


/* thx aramosf@unsec.net for the nice regexp! */

// Linux
char tcpcommand1[]= "netstat -tan | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
char udpcommand1[]= "netstat -uan | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;

// Alternative commands, needs iproute2
char tcpcommand2[]= "ss -tan sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
char udpcommand2[]= "ss -uan sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;

// fuser commands
char fuserTCPcommand[]= "fuser -v -n tcp %d 2>&1" ;
char fuserUDPcommand[]= "fuser -v -n udp %d 2>&1" ;

// lsof commands
char lsofTCPcommand[]= "lsof +c 0 -iTCP:%d" ;
char lsofUDPcommand[]= "lsof +c 0 -iUDP:%d" ;

// OpenBSD
// char tcpcommand[]= "netstat -an -p tcp | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
// char udpcommand[]= "netstat -an -p udp| sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;


// Solaris
// char tcpcommand[]= "netstat -an -P tcp | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;
// char udpcommand[]= "netstat -an -P udp| sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'" ;



/*
 *  Run a command to get more information about a port. 
 */
static void print_info(const char *prog_name, const char *command_fmt, int port)
{

   char buffer[1000];
   FILE* fp;

   sprintf(buffer, command_fmt, port);
   fp = popen(buffer, "r") ;

   if (NULL == fp)
   {
      warnln(verbose, unlog, "Couldn't run command: %s", buffer) ;
      return ;
   }

   msgln(unlog, 1, "%s reports :", prog_name) ;

   while (NULL != fgets(buffer, 1000, fp))
   {
      msgln(unlog, 1, buffer) ;
   }

   pclose(fp);
}

/* Print a port, optionally querying info about it via lsof or fuser. */
void print_port(enum Proto proto, int port)
{
      msgln(unlog, 0, "\nFound Hidden port that not appears in %s: %i", checker, port) ;
      if (1 == use_fuser)
      {
         if (TCP == proto)
         {
            print_info("fuser", fuserTCPcommand, port);
         }
         else
         {
            print_info("fuser", fuserUDPcommand, port);
         }
      }
      if (1 == use_lsof)
      {
         if (TCP == proto)
         {
            print_info("lsof", lsofTCPcommand, port);
         }
         else
         {
            print_info("lsof", lsofUDPcommand, port);
         }
      }
}


/*
 * Check if port is seen by netstat.
 *
 * If not, report it and optionnally run lsof and/or fuser
 * to show more info.
 */
int checkoneport(int port, char command[], enum Proto proto)
{
   int ok = 0;
   char ports[30];
   char compare[100];

   FILE *fich_tmp ;

   if (NULL != (fich_tmp=popen (command, "r")))
   {
      sprintf(compare,"%i\n",port);
      while ((NULL != fgets(ports, 30, fich_tmp)) && ok == 0) {
         if (strcmp(ports, compare) == 0) {ok = 1;}
      }
      pclose(fich_tmp);
   }
   else
   {
      die(unlog, "Couldn't execute command : %s while checking port %d", command, port) ;
   }
   return(ok) ;
}

/*
 * Check all TCP ports one by one.
 */
static void print_hidden_TCP_ports_1_by_1(enum Proto proto)
{
   int i ;
   char tcpcommand[512] ;

   hidden_found = 0 ;
   for (i =1; i <= 65535; i++)
   {
      int socket_desc;
      struct sockaddr_in address;

      if ( -1 != (socket_desc=socket(AF_INET,SOCK_STREAM,0)))
      {
         address.sin_family = AF_INET;
         address.sin_addr.s_addr = INADDR_ANY;
         address.sin_port = htons(i);
         errno= 0 ;
         if ( -1 != bind(socket_desc,(struct sockaddr *)&address,sizeof(address)))
         {
            listen(socket_desc,1);
            if ( EADDRINUSE == errno )    // port is listened by another process
            {
               if (1 == use_ss)
               {
                  sprintf(tcpcommand, tcpcommand2, i) ;
               }
               else
               {
                  strncpy(tcpcommand, tcpcommand1, 512) ;
               }
               if (0 == checkoneport(i, tcpcommand, TCP))
               {
                  // test again
                  listen(socket_desc,1);
                  if ( EADDRINUSE == errno )    // port is still listened by another process
                  {
                     hidden_found++;
                     print_port(proto, i) ;
                  }
               }
               close(socket_desc);
            }
            else
            {
               close(socket_desc);
            }
         }
         else
         {
            if (EADDRINUSE == errno)    //port is in use by another process
            {
               if (1 == use_ss)
               {
                  sprintf(tcpcommand, tcpcommand2, i) ;
               }
               else
               {
                  strncpy(tcpcommand, tcpcommand1, 512) ;
               }
               if (0 == checkoneport(i, tcpcommand, TCP))
               {
                  // test again
                  if ( -1 == bind(socket_desc,(struct sockaddr *)&address,sizeof(address)))
                  {
                     if ( EADDRINUSE == errno )    // port is still used by another process
                     {
                        hidden_found++;
                        print_port(proto, i) ;
                     }
                     else
                     {
                        warnln(verbose, unlog, "can't bind to socket while checking port %d", i) ;
                     }
                     close(socket_desc);
                  }
               }
               else
               {
                  close(socket_desc);
               }
            }
         }
      }
      else
      {
         warnln(verbose, unlog, "can't create socket while checking port %d/tcp", i) ;
      }
   }
}

/*
 * Check all UDP ports one by one.
 */
static void print_hidden_UDP_ports_1_by_1(enum Proto proto)
{
   int u ;
   char udpcommand[512] ;

   hidden_found = 0 ;

   for (u = 1; u <= 65535; u++)
   {
      int socket_desc;
      struct sockaddr_in address;

      if ( -1 != (socket_desc=socket(AF_INET,SOCK_DGRAM,0)))
      {
         address.sin_family = AF_INET;
         address.sin_addr.s_addr = INADDR_ANY;
         address.sin_port = htons(u);
         errno= 0 ;
         if ( 0 != bind(socket_desc,(struct sockaddr *)&address,sizeof(address)))
         {
            if ( EADDRINUSE == errno )   //port is in use by another process
            {
               if (1 == use_ss)
               {
                  sprintf(udpcommand, udpcommand2, u) ;
               }
               else
               {
                  strncpy(udpcommand, udpcommand1, 512) ;
               }
               ;
               if (0 == checkoneport(u, udpcommand, UDP))
               {
                  // test again
                  if ( 0 != bind(socket_desc,(struct sockaddr *)&address,sizeof(address)))    // port is still in use by another process
                  {
                     if ( EADDRINUSE == errno )   //port is in use by another process
                     {
                        hidden_found++;
                        print_port(proto, u) ;
                     }
                  }
               }
               close(socket_desc);
            }
            else      // other error
            {
               close(socket_desc);
               warnln(verbose, unlog, "can't bind to socket while checking port %d", u) ;
            }
         }
         else  // port is available
         {
            close(socket_desc);
         }
      }
      else 
      {
         warnln(verbose, unlog, "can't create socket while checking port %d/udp", u) ;
      }
   }
}

static struct argp_option options[] =
{
	{ "show-fuser", 'f', 0, OPTION_ARG_OPTIONAL, "show fuser output for hidden ports" },
	{ "show-lsof", 'o', 0, OPTION_ARG_OPTIONAL, "show lsof output for hidden ports" },
	{ "use-quickver", 's', 0, OPTION_ARG_OPTIONAL, "use very quick version for server with lot of opened ports" },
	{ "use-netstat", 'n', 0, OPTION_ARG_OPTIONAL, "use netstat instead of ss" },
	{ "logfile", 'l', 0, OPTION_ARG_OPTIONAL, "log result into unhide-tcp.log file", 0 },
	{ "verbose", 'v', 0, OPTION_ARG_OPTIONAL, "verbose", 0 },
	{ NULL, 0, NULL, 0, NULL, 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
	struct arguments* arguments = (struct arguments*) state->input;

	switch (key)
	{
	case 'v':
		verbose = 1;
		break;
		
	case 'l': 
		logtofile = 1;
		break;
		
	case 'f': 
		use_fuser = 1 ;
		break;
		
	case 'o': 
		use_lsof = 1 ;
		break;
		
	case 's': 
		use_quick = 1 ;
		break;
		
	case 'n': 
		use_ss = 0 ;
		break;

	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };


/*
 * Look for TCP and UDP ports that are hidden to netstat.
 *
 * Returns 0 if none is found, 1 if there is some internal error, 4 if TCP
 * hidden ports were found, 8 if UDP hidden ports were found or 12 (4 & 8) if
 * both were found.
 */
int main(int argc, char  **argv) 
{
   int ret_code = 0;

   printf("%s\n%s", argp_program_version, header);

   if(getuid() != 0){
      die(unlog, "You must be root to run %s !", argv[0]) ;
   }
   
   argp_parse(&argp, argc, argv, 0, 0, NULL);   
   
   if (1 == logtofile) 
   {
      unlog = init_log(logtofile, header, "unhide-tcp") ;
   }

   if (1 == use_ss)
   {
      strncpy(checker, "ss", 10);
   }
   else
   {
      strncpy(checker, "netstat", 10);
   }
   
   setpriority(PRIO_PROCESS,0,-20);  /* reduce risk of race condition - may fail, dont care */
   
   msgln(unlog, 0, "[*]Starting TCP checking") ;
   if (1 == use_quick)
   {
      print_hidden_ports(TCP);
   }
   else
   {
      print_hidden_TCP_ports_1_by_1(TCP) ;
   }
   if (hidden_found)
   {
      ret_code += 4;
   }

   msgln(unlog, 0, "[*]Starting UDP checking") ;
   if (1 == use_quick)
   {
      print_hidden_ports(UDP);
   }
   else
   {
      print_hidden_UDP_ports_1_by_1(UDP) ;
   }
   if (hidden_found)
   {
      ret_code += 8;
   }

   if (logtofile == 1)
   {
      close_log(unlog, "unhide-tcp") ;
   }
   return(ret_code);

}

