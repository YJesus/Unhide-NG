/*
		  http://sourceforge.net/projects/unhide/
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
#include <string.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <dirent.h>

#define MAX_VALUE(a) (((unsigned long long)1 << (sizeof(a) * CHAR_BIT)) - 1)

typedef enum BOOL_e
{
	FALSE_ = 0,
	TRUE_ = 1
} BOOL_t;

const char* argp_program_version = "unhide-gids 20190207";
const char* argp_program_bug_address = "http://www.unhide-forensics.info";

static char doc[] =
"unhide-gids options:\
\v-";

static char args_doc[] = " ";

const char header[] =
"Copyright (c) 2019 Yago Jesus, Patrick Gouin & David Reguera Garcia aka Dreg\n"
"License GPLv3+ : GNU GPL version 3 or later\n"
"http://www.unhide-forensics.info\n\n"
"we recommend you execute first --copy-with-random-name-to=path or --copy-with-random-name-to-tmp to avoid unhide detection\n\n";

struct arguments
{
	char* random_to_path;
	BOOL_t processes_gids;
	BOOL_t files_gids;
};

enum CMD_OPT_e
{
	OPT_EMPTY = 1,
	OPT_COPY_RANDOM_TO_PATH,
	OPT_COPY_RANDOM_TO_TMP,
	OPT_ONLY_PROCESSES_GIDS,
	OPT_ONLY_FILES_GIDS
};

static struct argp_option options[] =
{
	{ "copy-with-random-name-to", OPT_COPY_RANDOM_TO_PATH, "FILE", OPTION_ARG_OPTIONAL, "Copy itself with a random name to a specific path. Example: --copy-with-random-name-to=/root" },
	{ "copy-with-random-name-to-tmp", OPT_COPY_RANDOM_TO_TMP, 0, OPTION_ARG_OPTIONAL, "Copy itself with a random name to default tmp path" },
	{ "processes-gids", OPT_ONLY_PROCESSES_GIDS, 0, OPTION_ARG_OPTIONAL, "bruteforce processes GIDs" },
	{ "files-gids", OPT_ONLY_FILES_GIDS, 0, OPTION_ARG_OPTIONAL, "bruteforce files GIDs" },
	{ NULL, 0, NULL, 0, NULL, 0 }
};

BOOL_t IsDirExist(char* path)
{
	struct stat st;

	memset(&st, 0, sizeof(st));

	if (NULL == path)
	{
		return FALSE_;
	}

	if (stat(path, &st) == 0)
	{
		return TRUE_;
	}

	return FALSE_;
}

BOOL_t GetTempPath(char* tmp_path, size_t size_tmp_path)
{
	char* tmp_path_aux = NULL;

	if ((NULL == tmp_path) || (size_tmp_path < PATH_MAX))
	{
		return FALSE_;
	}

	memset(tmp_path, 0, size_tmp_path);

	tmp_path_aux = (char*)getenv("TMPDIR");
	if (NULL == tmp_path_aux)
	{
		tmp_path_aux = (char*)getenv("TMP");
		if (NULL == tmp_path_aux)
		{
			tmp_path_aux = (char*)getenv("TEMP");
			if (NULL == tmp_path_aux)
			{
				tmp_path_aux = (char*)getenv("TEMPDIR");
				if (NULL == tmp_path_aux)
				{
					tmp_path_aux = "/tmp";
				}
			}
		}
	}

	if (NULL != tmp_path_aux)
	{
		if (FALSE_ == IsDirExist(tmp_path_aux))
		{
			return FALSE_;
		}

		if ((strlen(tmp_path_aux) + 1) < PATH_MAX)
		{
			strcpy(tmp_path, tmp_path_aux);

			return TRUE_;
		}
	}

	return FALSE_;
}


static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
	struct arguments* arguments = (struct arguments*) state->input;

	switch (key)
	{

	case OPT_COPY_RANDOM_TO_PATH:
	case OPT_COPY_RANDOM_TO_TMP:
		if (NULL != arguments->random_to_path)
		{
			fprintf(stderr, "error: you can only use --copy-with-random-name-to or --copy-with-random-name-to-tmp at the same time.\n");

			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}

		if (OPT_COPY_RANDOM_TO_PATH == key)
		{
			arguments->random_to_path = calloc(1, strlen(arg) + 1);
			if (NULL != arguments->random_to_path)
			{
				strcpy(arguments->random_to_path, arg);

				if (FALSE_ == IsDirExist(arguments->random_to_path))
				{
					fprintf(stderr, "error: custom tmp dir dont exist: %s\n", arguments->random_to_path);
					free(arguments->random_to_path);
					arguments->random_to_path = NULL;
				}
			}
		}
		else if (OPT_COPY_RANDOM_TO_TMP == key)
		{
			arguments->random_to_path = calloc(1, PATH_MAX);
			if (NULL != arguments->random_to_path)
			{
				if (FALSE_ == GetTempPath(arguments->random_to_path, PATH_MAX))
				{
					fprintf(stderr, "error: tmp dir dont exist.\n");
					free(arguments->random_to_path);
					arguments->random_to_path = NULL;
				}
			}
		}

		if (NULL == arguments->random_to_path)
		{
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}

		break;

	case OPT_ONLY_PROCESSES_GIDS:
		arguments->processes_gids = TRUE_;
		break;

	case OPT_ONLY_FILES_GIDS:
		arguments->files_gids = TRUE_;
		break;


	case ARGP_KEY_END:
		if (NULL == arguments->random_to_path)
		{
			if ((!arguments->processes_gids) && (!arguments->files_gids))
			{
				fprintf(stderr, "error: you need specify --processes-gids or --files-gids\n");

				argp_usage(state);
				return ARGP_ERR_UNKNOWN;
			}
			else if ((arguments->processes_gids) && (arguments->files_gids))
			{
				fprintf(stderr, "error: you can only specify --processes-gids or --files-gids at the same time\n");

				argp_usage(state);
				return ARGP_ERR_UNKNOWN;
			}
		}
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

typedef enum GEN_RAND_STR_e
{
	GRS_ALPHANUM = 0,
	GRS_NUM,
	GRS_ALPHA

} GEN_RAND_STR_e_t;

BOOL_t GenerateRandomString(char* str, GEN_RAND_STR_e_t type, int min, int max)
{
	char charset_alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char charset_num[] = "0123456789";
	char charset_alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char* charset = NULL;
	size_t size_charset = 0;
	int random_nr_chars = 0;

	switch (type)
	{
	case GRS_ALPHANUM:
		charset = charset_alphanum;
		size_charset = sizeof(charset_alphanum);
		break;

	case GRS_NUM:
		charset = charset_num;
		size_charset = sizeof(charset_num);
		break;

	case GRS_ALPHA:
		charset = charset_alpha;
		size_charset = sizeof(charset_alpha);
		break;

	default:

		return FALSE_;

		break;
	}

	srand((unsigned int)time(NULL));

	random_nr_chars = rand() % max;
	while (random_nr_chars < min)
	{
		random_nr_chars++;
	}

	do
	{
		*str = charset[rand() % (((int)size_charset) - 1)];
		str++;
	} while (random_nr_chars-- > 0);

	return TRUE_;
}


BOOL_t GenerateRandomNamePath(char* path, char* random_path)
{
	char* end_str = NULL;

	if ((NULL == path) || (NULL == random_path))
	{
		return FALSE_;
	}

	strcpy(random_path, path);
	end_str = &random_path[strlen(random_path) - 1];
	if ('/' != *end_str)
	{
		end_str++;
		*end_str = '/';
	}
	end_str++;

	return GenerateRandomString(end_str, GRS_ALPHANUM, 7, 9);
}

BOOL_t CopyItselfToRandomPath(char* program, char* dst_path)
{
	FILE* file_src = NULL;
	FILE* file_dst = NULL;
	char file_dst_random_name[PATH_MAX];
	char cmd_line[PATH_MAX * 2];
	char block[512];
	size_t bytes_readed = 0;
	BOOL_t retf = FALSE_;

	memset(cmd_line, 0, sizeof(cmd_line));
	memset(file_dst_random_name, 0, sizeof(file_dst_random_name));
	memset(block, 0, sizeof(block));


	if ((NULL == program) || (NULL == dst_path))
	{
		fprintf(stderr, "error: program name or dst path is NULL.\n");
		return FALSE_;
	}

	do 
	{
		memset(file_dst_random_name, 0, sizeof(file_dst_random_name));
		GenerateRandomNamePath(dst_path, file_dst_random_name);
	} while (IsDirExist(file_dst_random_name));

	printf("random name generated: %s\n", file_dst_random_name);

	file_src = fopen(program, "rb");
	if (NULL != file_src)
	{
		file_dst = fopen(file_dst_random_name, "wb+");
		if (NULL != file_dst)
		{
			do
			{
				bytes_readed = fread(block, 1, sizeof(block), file_src);
				fwrite(block, bytes_readed, 1, file_dst);
			} while (0 != bytes_readed);

			retf = TRUE_;

			fclose(file_dst);

			if (chmod(file_dst_random_name, S_IRWXU | S_IXGRP | S_IRGRP | S_IXOTH | S_IROTH) == 0)
			{
				sprintf(cmd_line, "%s t", file_dst_random_name);
				printf("testing new executable with cmdline: %s\n", cmd_line);
				if (system(cmd_line) == 0)
				{
					retf = TRUE_;
				}
				else
				{
					fprintf(stderr, "error: testing execution of the random name executable, maybe is in noexec path??\n");
				}
			}
			else
			{
				fprintf(stderr, "error: chmod to new file fail\n");
			}

			printf("\ncopied! please run the new copy of unhide executable by hand: %s\n", file_dst_random_name);
		}
		fclose(file_src);
	}
	

	return retf;
}

static int ExistStartNumericInDir(char* path, char* pid_string, int* exist)
{
	DIR* dir;
	struct dirent* ent;
	register char c;

	*exist = 0;

	if ((dir = opendir(path)) != NULL)
	{
		while ((ent = readdir(dir)) != NULL)
		{
			c = ent->d_name[0];

			if (c >= '0' && c <= '9' && strcmp(ent->d_name, pid_string) == 0)
			{
				*exist = 1;
				break;
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

void _BruteForceGIDProcessesParent(pid_t child_pid, int fd_child, int fd_parent, gid_t first_gid, gid_t last_gid)
{
	ssize_t write_ret = 0;
	ssize_t read_ret = 0;
	int exist_in_proc = 0;
	int exist_in_proc_ret = 0;
	unsigned int gid_detected = 0;
	unsigned int glast_gid = 0;
	unsigned int actual_gid = 0;
	int read_state = 0;
	char procfs_status_file_name[PATH_MAX];
	char procfs_childpid_dir_name[PATH_MAX];
	char pid_string[PATH_MAX];
	char* type = NULL;
	unsigned int i = 0;

	memset(procfs_status_file_name, 0, sizeof(procfs_status_file_name));
	sprintf(procfs_status_file_name, "/proc/%d/status", child_pid);

	memset(procfs_childpid_dir_name, 0, sizeof(procfs_childpid_dir_name));
	sprintf(procfs_childpid_dir_name, "/proc/%d", child_pid);

	memset(pid_string, 0, sizeof(pid_string));
	sprintf(pid_string, "%d", child_pid);

	printf("starting brute... please be patient\n");

	read_state = 1;
	actual_gid = (unsigned int) first_gid;
	do
	{
		if ((i++ % 100000) == 0)
		{
			printf("actual gid: %u ....\n", actual_gid);
		}

		glast_gid = gid_detected;
		read_ret = read(fd_child, &gid_detected, sizeof(gid_detected));
	
		exist_in_proc = 0;
		exist_in_proc_ret = ExistStartNumericInDir((char*)"/proc/", pid_string, &exist_in_proc);

		write_ret = write(fd_parent, &read_state, sizeof(read_state));
		if ((read_ret == -1) || (read_ret == 0))
		{
			fprintf(stderr, "error: brute GID processes broken read fd_child pipe with child!! the GID range of this thread will be stopped...\n");
			break;
		}
		if ((write_ret == -1) || (write_ret == 0))
		{
			fprintf(stderr, "error: brute GID processes broken write fd_parent pipe with child!! the GID range of this thread will be stopped... \n");
			break;
		}

		if (exist_in_proc_ret == -1)
		{
			type = (char*) "/proc dir innaccesible";
		}
		else if (exist_in_proc == 0)
		{
			type = (char*) "gid hidden from readdir proc";
		}
		else if (gid_detected != actual_gid)
		{
			type = (char*) "gid_detected != actual_gid";
		}
		else if (gid_detected == glast_gid)
		{
			type = (char*) "gid_detected == last_gid";
		}
		else if (gid_detected == 0)
		{
			type = (char*) "gid_detected == 0";
		}

		if (NULL != type)
		{
			printf("WARNING!!: possible rookit detected: gid_detected %u, actual_gid: %u, glast_gid: %u, type: %s\n", gid_detected, actual_gid, glast_gid, type);
			break;
		}
	} while (actual_gid++ != (unsigned int) last_gid);
}

void _BruteForceGIDProcessesChild(int fd_child, int fd_parent, gid_t first_gid, gid_t last_gid)
{
	ssize_t write_ret = 0;
	ssize_t read_ret = 0;
	int set_gid_ret = 0;
	unsigned int gid_detected = 0;
	unsigned int glast_gid = 0;
	unsigned int actual_gid = 0;
	int read_state = 0;
	unsigned int gid_aux = 0;

	actual_gid = (unsigned int) first_gid;
	do
	{
		gid_detected = 0;
		set_gid_ret = setgid(actual_gid);
		glast_gid = gid_detected;
		gid_detected = getgid();

		write_ret = write(fd_child, &gid_detected, sizeof(gid_detected));
		read_ret = read(fd_parent, &read_state, sizeof(read_state));

		if ((write_ret == 0) || (write_ret == -1))
		{
			break;
		}
		if ((read_ret == 0) || (read_ret == -1))
		{
			break;
		}

		if ((actual_gid != gid_detected) ||
			(glast_gid == gid_detected) ||
			(set_gid_ret != 0))
		{
			/* possible rootkit detected */

			gid_aux = 0;
			write(fd_child, &gid_aux, sizeof(gid_aux));

			break;
		}
	} while (actual_gid++ != (unsigned int) last_gid);
}


void BruteForceGIDProcessesParent(pid_t child_pid, char* fifo_child, char* fifo_parent, gid_t first_gid, gid_t last_gid)
{
	int fd_child = 0;
	int fd_parent = 0;

	fd_child = open(fifo_child, O_RDONLY);
	if (fd_child != -1)
	{
		fd_parent = open(fifo_parent, O_WRONLY);
		if (fd_parent != -1)
		{
			_BruteForceGIDProcessesParent(child_pid, fd_child, fd_parent, first_gid, last_gid);

			close(fd_parent);
		}
		close(fd_child);
	}
}

void BruteForceGIDProcessesChild(char* fifo_child, char* fifo_parent, gid_t first_gid, gid_t last_gid)
{
	int fd_child = 0;
	int fd_parent = 0;

	fd_child = open(fifo_child, O_WRONLY);
	if (fd_child != -1)
	{
		fd_parent = open(fifo_parent, O_RDONLY);
		if (fd_parent != -1)
		{
			_BruteForceGIDProcessesChild(fd_child, fd_parent, first_gid, last_gid);

			close(fd_parent);
		}
		close(fd_child);
	}
}

void* BruteForceGIDProcesses(gid_t first_gid, gid_t last_gid)
{
	char fifo_name[PATH_MAX];
	char fifo_parent[PATH_MAX];
	char fifo_child[PATH_MAX];
	char tmp_dir[PATH_MAX];
	pid_t child_pid;

	memset(fifo_name, 0, sizeof(fifo_name));
	memset(fifo_parent, 0, sizeof(fifo_parent));
	memset(fifo_child, 0, sizeof(fifo_child));
	memset(tmp_dir, 0, sizeof(tmp_dir));

	GenerateRandomString(fifo_name, GRS_ALPHANUM, 7, 9);

	GetTempPath(tmp_dir, sizeof(tmp_dir));

	sprintf(fifo_parent, "%s/%s.parent_processes", tmp_dir, fifo_name);
	sprintf(fifo_child, "%s/%s.child_processes", tmp_dir, fifo_name);

	printf("brute GID processes\n\tGID range: %u - %u\n\t%s \n\t%s\n", first_gid, last_gid, fifo_parent, fifo_child);

	if (mkfifo(fifo_parent, 0666) == 0)
	{
		if (mkfifo(fifo_child, 0666) == 0)
		{
			child_pid = fork();
			if (child_pid != -1)
			{
				if (child_pid == 0)
				{
					BruteForceGIDProcessesChild(fifo_child, fifo_parent, first_gid, last_gid); 
				}
				else
				{
					BruteForceGIDProcessesParent(child_pid, fifo_child, fifo_parent, first_gid, last_gid);
				}
			}
			unlink(fifo_child);
		}
		unlink(fifo_parent);
	}

	return NULL;
}

void* BruteForceGIDFiles(gid_t first_gid, gid_t last_gid)
{
	char file_name[PATH_MAX];
	char full_path[PATH_MAX];
	unsigned int gid_detected = 0;
	unsigned int actual_gid = 0;
	unsigned int glast_gid = 0;
	uid_t my_uid;
	struct stat statbuf;
	int chown_ret = 0;
	int stat_ret = 0;
	int exist_file_ret;
	int exist_in_tmp;
	char file_name_ext[PATH_MAX];
	char tmp_dir[PATH_MAX];
	unsigned int i = 0;
	char* type = NULL;

	my_uid = getuid();

	memset(file_name, 0, sizeof(file_name));
	memset(full_path, 0, sizeof(full_path));
	memset(file_name_ext, 0, sizeof(file_name_ext));
	memset(tmp_dir, 0, sizeof(tmp_dir));

	GenerateRandomString(file_name, GRS_NUM, 7, 9);

	GetTempPath(tmp_dir, sizeof(tmp_dir));

	sprintf(file_name_ext, "%s.files", file_name);

	sprintf(full_path, "%s/%s", tmp_dir, file_name_ext);

	printf("brute GID files\n\tGID range: %u - %u\n\t%s\n", first_gid, last_gid, full_path);

	fclose(fopen(full_path, "wb+"));

	actual_gid = first_gid;
	do
	{
		if ((i++ % 100000) == 0)
		{
			printf("actual gid: %u ....\n", actual_gid);
		}

		chown_ret = chown(full_path, my_uid, actual_gid);
		gid_detected = 0;
		statbuf.st_gid = 0;
		stat_ret = stat(full_path, &statbuf);
		if (stat_ret != -1)
		{
			glast_gid = gid_detected;
			gid_detected = statbuf.st_gid;
		}
		exist_in_tmp = 0;
		exist_file_ret = ExistStartNumericInDir(tmp_dir, file_name_ext, &exist_in_tmp);

		if (exist_file_ret == -1)
		{
			type = (char*) "tmp dir innaccesible";
		}
		else if (exist_in_tmp == 0)
		{
			type = (char*) "gid hidden from readdir tmp";
		}
		else if (chown_ret == -1)
		{
			type = (char*) "chown hooked";
		}
		else if (stat_ret == -1)
		{
			type = (char*) "stat hooked";
		}
		else if (gid_detected != actual_gid)
		{
			type = (char*) "gid_detected != actual_gid";
		}
		else if (gid_detected == last_gid)
		{
			type = (char*) "gid_detected == last_gid";
		}
		else if (gid_detected == 0)
		{
			type = (char*) "gid_detected == 0";
		}

		if (NULL != type)
		{
			printf("WARNING!!: possible rookit detected: type: %s - extra info : chown_ret: %d, stat_ret : %d, exist_file_ret : %d, exist_in_tmp : %d, gid_detected : %u, actual_gid : %u, last_gid : %u\n",
				type, chown_ret, stat_ret, exist_file_ret, exist_in_tmp, gid_detected, actual_gid, glast_gid);
			break;
		}

	} while (actual_gid++ != last_gid);

	unlink(full_path);

	return NULL;
}

int main(int argc, char *argv[])
{
	struct arguments arguments;
	int retf = 1;

	memset(&arguments, 0, sizeof(arguments));

	if (argc > 1)
	{
		if ((argv[1][0] == 't') && (argv[1][1] == '\0'))
		{
			puts("executabled tested!");
			return 0;
		}
	}

	printf("%s\n%s", argp_program_version, header);

	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	if (NULL != arguments.random_to_path)
	{
		retf = CopyItselfToRandomPath(argv[0], arguments.random_to_path) == TRUE_ ? 0 : 1;

		free(arguments.random_to_path);
	}
	else if (arguments.files_gids)
	{
		BruteForceGIDFiles(1, MAX_VALUE(gid_t) - 1);
	}
	else if (arguments.processes_gids)
	{
		BruteForceGIDProcesses(1, MAX_VALUE(gid_t) - 1);
	}
	else
	{
		fprintf(stderr, "error: wtf\n");
	}

	puts("bye");

	return retf;
}