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

#include "unhide-linux.h"

#if UNH_COMPILE_LOW == 1

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define BUF_SIZE 0x500000

struct linux_dirent {
	long           d_ino;
	off_t          d_off;
	unsigned short d_reclen;
	char           d_name[];
};

typedef struct PID_TIMES_s
{
	pid_t pid;
	size_t times;
} NAME_TIMES_t;


static inline int ExistPIDInProc(pid_t pid, int* exist)
{
	DIR* dir;
	struct dirent* ent;
	register char c;
	pid_t current_pid = 0;

	*exist = 0;

	if ((dir = opendir("/proc")) != NULL)
	{
		while ((ent = readdir(dir)) != NULL)
		{
			c = ent->d_name[0];
			if (c >= '0' && c <= '9')
			{
				current_pid = atoi(ent->d_name);
				if (current_pid == pid)
				{
					*exist = 1;
					break;
				}
			}
		}
		closedir(dir);
	}
	else
	{
		return -1;
	}

	return 0;
}


char buf[BUF_SIZE];

#pragma GCC push_options
#pragma GCC optimize("O0")
int mainw(NAME_TIMES_t** name_times, size_t* last_elemt)
{
	int nread = 0;
	struct linux_dirent* d = NULL;
	int bpos = 0;
	char c;
	pid_t current_pid = 0;
	size_t i = 0;
	int found = 0;


	/*
	TO DO: iterate more times buf...

	for ( ; ; ) {
	   nread = getdents....
	   if (nread == -1)
		   break;

	   if (nread == 0)
		   break;

	*/

#ifdef __x86_64
	__asm__("mov %0, %%rax\n\t"
		:
		: "r"(buf)
		:
	);

	__asm__(
		"push %rsi\n\t"
		"push %rdi\n\t"
		"push %rdx\n\t"
	);

	__asm__(
		"push %rax\n\t"
		"xor %rax, %rax\n\t"
		"push %rax\n\t"
		"push $0x2e\n\t"
		"mov $0x02, %al\n\t"
		"mov %rsp, %rdi\n\t"
		"xor %rsi, %rsi\n\t"
		"xor %rdx, %rdx\n\t"
		"syscall\n\t" /* sys_open(".") */

		"mov %rax, %rdi\n\t"
		"xor %rdx, %rdx\n\t"
		"xor %rax, %rax\n\t"
		"mov $0x500000, %rdx\n\t"

		"pop %rsi\n\t"
		"pop %rsi\n\t"
		"pop %rsi\n\t"

		"mov $0x4e, %al\n\t"
		"syscall\n\t" /* getdents() */

	);

	__asm__("movl %%eax, %0" : "=r"(nread));

	__asm__(
		"pop %rdx\n\t"
		"pop %rdi\n\t"
		"pop %rsi\n\t"
	);
#else

	__asm__("mov %0, %%eax\n\t"
		:
		: "r"(buf)
		:
		);

	__asm__("pushal;");

	__asm__(
		"push %eax\n\t"
		"xor %eax, %eax\n\t"
		"push %eax\n\t"
		"push $0x2e\n\t"
		"mov $0x05, %al\n\t"
		"mov %esp, %ebx\n\t"
		"xor %ecx, %ecx\n\t"
		"xor %edx, %edx\n\t"
		"int $0x80\n\t" /* sys_open(".") */

		"mov %eax, %ebx\n\t"
		"xor %eax, %eax\n\t"
		"mov $0x500000, %edx\n\t"

		"pop %ecx\n\t"
		"pop %ecx\n\t"
		"pop %ecx\n\t"

		"mov $0x8d, %al\n\t"
		"int $0x80\n\t" /* getdents() */

	);

	__asm__("movl %%eax, %0" : "=r"(nread));

	__asm__("popal;");

#endif 

	for (bpos = 0; bpos < nread;) 
	{
		d = (struct linux_dirent *) (buf + bpos);
		if ((0 != d->d_ino)  &&  (NULL != d->d_name))
		{
			c = d->d_name[0];

			//printf("%s\n", (char *)d->d_name); fflush(stdout);

			if (c >= '0' && c <= '9')
			{
				current_pid = atoi(d->d_name);
				found = 0;
				for (i = 0; i < *last_elemt; i++)
				{
					if (current_pid == (*name_times)[i].pid)
					{
						found = 1;
						break;
					}
				}
				if (!found)
				{
					*last_elemt = *last_elemt + 1;
					*name_times = realloc(*name_times, sizeof(NAME_TIMES_t) * (*last_elemt));
					(*name_times)[*last_elemt - 1].pid = current_pid;
					(*name_times)[*last_elemt - 1].times = 1;
				}
			}
		}
		bpos += d->d_reclen;
	}

    return 0;
}
#pragma GCC pop_options

void checklow(void)
{
	NAME_TIMES_t* name_times = NULL;
	size_t last_elemt = 0;
	int i = 0;
	int j = 0;
	int exist = 0;

	msgln(unlog, 0, "[*]Searching for Hidden processes through linux readdir vs ASM getdents\n") ;

	chdir("/proc");

	name_times = (NAME_TIMES_t*)calloc(1, sizeof(NAME_TIMES_t));
	if (NULL == name_times)
	{
		return;
	}

	for (i = 0; i < 30; i++)
	{
		mainw(&name_times, &last_elemt);

		for (j = 0; j < last_elemt; j++)
		{
			exist = 0;
			ExistPIDInProc(name_times[j].pid, &exist);
			if (0 == exist)
			{
				name_times[j].times++;
			}
		}
	}


	for (i = 0; i < last_elemt; i++)
	{
		if (name_times[i].times != 1)
		{
			msgln(unlog, 0, "WARNING!!! possible PID hidden in /proc/%d (times: %d)\n", name_times[i].pid, name_times[i].times);
			printbadpid (name_times[i].pid); 
		}
	}

	free(name_times);
}

#endif 
