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
	char* report_path;
	int processes_gids;
	int files_gids;
};

enum CMD_OPT_e
{
	OPT_EMPTY = 1,
	OPT_COPY_RANDOM_TO_PATH,
	OPT_COPY_RANDOM_TO_TMP,
	OPT_REPORT_PATH,
	OPT_ONLY_PROCESSES_GIDS,
	OPT_ONLY_FILES_GIDS
};

static struct argp_option options[] =
{
	{ "copy-with-random-name-to", OPT_COPY_RANDOM_TO_PATH, "FILE", OPTION_ARG_OPTIONAL, "Copy itself with a random name to a specific path. Example: --copy-with-random-name-to=/root" },
	{ "copy-with-random-name-to-tmp", OPT_COPY_RANDOM_TO_TMP, 0, OPTION_ARG_OPTIONAL, "Copy itself with a random name to default tmp path" },
	{ "report-path", OPT_REPORT_PATH, "FILE", OPTION_ARG_OPTIONAL, "Set new report path. it needs also the name. Example: --report-path=/root/analysis.txt" },
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

	case OPT_REPORT_PATH:
		if (TRUE_ == IsDirExist(arg))
		{
			fprintf(stderr, "error: report file already exist: %s\n", arg);
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		else
		{
			arguments->report_path = arg;
		}
		break;

	case OPT_ONLY_PROCESSES_GIDS:
		arguments->processes_gids = 1;
		break;

	case OPT_ONLY_FILES_GIDS:
		arguments->files_gids = 1;
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

BOOL_t GenerateRandomNamePath(char* path, char* random_path)
{
	char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int random_nr_chars = 0;
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

	srand((unsigned int)time(NULL));

	random_nr_chars = 7 + (rand() % 9);

	do
	{
		*end_str = charset[rand() % ((int)sizeof(charset) - 1)];
		end_str++;
	} while (random_nr_chars-- > 0);


	return TRUE_;
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

	printf("TMP path: %s\n", arguments.random_to_path);

	if (NULL != arguments.random_to_path)
	{
		retf = CopyItselfToRandomPath(argv[0], arguments.random_to_path) == TRUE_ ? 0 : 1;

		free(arguments.random_to_path);
	}

	puts("bye");

	return retf;
}