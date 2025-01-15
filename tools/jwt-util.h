/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <unistd.h>
#include <sys/wait.h>

static char *pipe_cmd;

static FILE *json_fp;

static int write_json(const char *title, const char *str)
{
	char *argv[4] = { "/bin/sh", "-c", NULL, NULL };
	int pipe_fd[2];
	int myfd = 0;
	pid_t pid;
	int status;

	if (json_fp == NULL)
		json_fp = stdout;

	if (pipe_cmd) {
		if (pipe(pipe_fd)) {
			perror(pipe_cmd);
			exit(EXIT_FAILURE);
		}

		argv[2] = pipe_cmd;
		pid = fork();

		if (pid == 0) {
			close(pipe_fd[1]);

			if (json_fp == stderr)
				dup2(STDERR_FILENO, STDOUT_FILENO);
			dup2(pipe_fd[0], STDIN_FILENO);
			close(pipe_fd[0]);

			execvp(argv[0], argv);

			perror("execvp");
			exit(EXIT_FAILURE);
		} else {
			close(pipe_fd[0]);
			myfd = pipe_fd[1];
		}
	}

	fprintf(json_fp, "\033[0;95m[%s]\033[0m\n", title);

	if (myfd) {
		if (write(myfd, str, strlen(str)) < 0) {
			perror(pipe_cmd);
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(json_fp, "\033[0;96m%s\033[0m\n", str);
	}

	if (myfd) {
		close(myfd);
		waitpid(pid, &status, 0);
		return WEXITSTATUS(status);
	}

	return 0;
}

static int __jwt_wcb(jwt_t *jwt, jwt_config_t *config)
{
	jwt_value_t jval;
	int ret = 0, result = 0;

	if (config == NULL)
		return 1;

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_header_get(jwt, &jval);
	if (!ret) {
		result |= write_json("HEADER", jval.json_val);
		free(jval.json_val);
	}

	jwt_set_GET_JSON(&jval, NULL);
	jval.pretty = 1;
	ret = jwt_grant_get(jwt, &jval);
	if (!ret) {
		result |= write_json("PAYLOAD", jval.json_val);
		free(jval.json_val);
	}

	return result;
}
