/* Copyright (C) 2024-2025 maClara, LLC <info@maclara-llc.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdio.h>
#include <unistd.h>

static char *pipe_cmd;

static FILE *json_fp;

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#endif

/* The length of the well-formed UTF-8 sequence (RFC 3629) that starts the
 * @len bytes at @s (at least one), or 0 if they do not start with one: a lead
 * byte C2-DF, E0-EF or F0-F4, followed by 1, 2 or 3 bytes of 80-BF, and not
 * cut short by @len. No byte past @len is read. */
static inline size_t utf8_seq_len(const unsigned char *s, size_t len)
{
	/* The range of the byte after the lead. Four leads narrow it, so that
	 * no code point has a second, overlong form and none is a surrogate
	 * or above U+10FFFF. */
	unsigned char lo = 0x80, hi = 0xbf;
	size_t n, i;

	if (s[0] >= 0xc2 && s[0] <= 0xdf)
		n = 2;
	else if (s[0] >= 0xe0 && s[0] <= 0xef)
		n = 3;
	else if (s[0] >= 0xf0 && s[0] <= 0xf4)
		n = 4;
	else
		return 0;	/* 80-BF, C0, C1 or F5-FF */

	if (s[0] == 0xe0)
		lo = 0xa0;	/* E0 80-9F would be below U+0800 */
	else if (s[0] == 0xed)
		hi = 0x9f;	/* ED A0-BF are U+D800 to U+DFFF */
	else if (s[0] == 0xf0)
		lo = 0x90;	/* F0 80-8F would be below U+10000 */
	else if (s[0] == 0xf4)
		hi = 0x8f;	/* F4 90-BF are above U+10FFFF */

	if (n > len)
		return 0;

	for (i = 1; i < n; i++) {
		if (s[i] < lo || s[i] > hi)
			return 0;
		lo = 0x80;
		hi = 0xbf;
	}

	return n;
}

/* Write the @len bytes of @str to @fp so that a UTF-8 terminal reads no
 * control character from them, but for the '\n' and '\t' that @keep_layout
 * keeps: text from a token can then neither move the cursor nor change
 * colours, titles or lines already printed. (A terminal that does not read
 * UTF-8 can still take a byte of a well-formed sequence, such as the 9B of
 * C3 9B, for a C1 control.) Byte by byte, never reading past @len:
 *  - a byte below 0x20 is written as \xNN, but for '\n' and '\t' when
 *    @keep_layout is set (the line breaks and indentation of a JSON dump);
 *  - 0x7f is written as \x7f;
 *  - bytes 0x20 to 0x7e are written as they are;
 *  - a byte from 0x80 up starts a UTF-8 sequence, which must be well formed
 *    (see utf8_seq_len()). A sequence for U+0080 to U+009F (C2 80 to C2 9F,
 *    the C1 controls) is written as \xNN for each of its bytes, any other
 *    as it is. A byte that does not start one is written as \xNN on its
 *    own, and the next byte is read as a new start.
 * NN is two lowercase hex digits. */
static inline void write_escaped(FILE *fp, const char *str, size_t len,
				 int keep_layout)
{
	const unsigned char *s = (const unsigned char *)str;
	size_t i = 0, run = 0;

	while (i < len) {
		unsigned char c = s[i];
		size_t n = 1;
		int esc;

		if (c < 0x80) {
			esc = (c < 0x20 || c == 0x7f) &&
			      !(keep_layout && (c == '\n' || c == '\t'));
		} else {
			n = utf8_seq_len(s + i, len - i);
			if (n == 0) {
				/* Not well-formed: this one byte. */
				n = 1;
				esc = 1;
			} else {
				/* C2 80-9F: U+0080 to U+009F. */
				esc = c == 0xc2 && s[i + 1] < 0xa0;
			}
		}

		if (!esc) {
			i += n;
			continue;
		}

		/* The bytes from run up to here are written as they are, in
		 * one go: @fp can be stderr, which has no buffer. */
		fwrite(s + run, 1, i - run, fp);
		for (; n > 0; n--, i++)
			fprintf(fp, "\\x%02x", s[i]);
		run = i;
	}

	fwrite(s + run, 1, i - run, fp);
}

static inline int write_json(const char *title, const char *str)
{
	int exit_code = 0;

	if (json_fp == NULL)
		json_fp = stdout;

	fprintf(json_fp, "\033[0;95m[%s]\033[0m\n", title);

#ifdef _WIN32
	FILE *pipe_fp = NULL;
	if (pipe_cmd) {
		pipe_fp = _popen(pipe_cmd, "w");
		if (!pipe_fp) {
			perror("popen");
			return -1;
		}
	}

	if (pipe_fp) {
		if (fwrite(str, 1, strlen(str), pipe_fp) < strlen(str)) {
			perror("fwrite");
			exit_code = EXIT_FAILURE;
		}

		/* A non-zero command status (or a failed close) fails the
		 * token, as on the POSIX path. */
		if (_pclose(pipe_fp) != 0)
			exit_code = EXIT_FAILURE;
	}
#else
	int pipe_fd[2];
	int myfd = 0;
	pid_t pid;
	int status;

	if (pipe_cmd) {
		char *argv[4] = { "/bin/sh", "-c", NULL, NULL };

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

	if (myfd) {
		if (write(myfd, str, strlen(str)) < 0) {
			perror(pipe_cmd);
			exit(EXIT_FAILURE);
		}
	}
#endif
	else {
		/* Inside a string the JSON encoders escape only the controls
		 * below 0x20, so the dump is escaped here as a token is, but
		 * keeps its layout. A --print command gets the JSON as it is. */
		fputs("\033[0;96m", json_fp);
		write_escaped(json_fp, str, strlen(str), 1);
		fputs("\033[0m\n", json_fp);
	}

#ifndef _WIN32
	if (myfd) {
		close(myfd);
		/* Only a command that ran to its end and exited 0 passes. One
		 * that a signal ended (a crash, say) has no exit status, and
		 * WEXITSTATUS() reads 0 for it. */
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
			exit_code = EXIT_FAILURE;
		else
			exit_code = WEXITSTATUS(status);
	}
#endif

	return exit_code;
}

static inline int __jwt_wcb(jwt_t *jwt, jwt_config_t *config)
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
	ret = jwt_claim_get(jwt, &jval);
	if (!ret) {
		result |= write_json("PAYLOAD", jval.json_val);
		free(jval.json_val);
	}

	return result;
}

#ifdef _WIN32
__declspec(dllimport) extern char **__argv;
static inline const char *get_progname(void)
{
	return __argv[0];
}
#else
extern const char *__progname;
static inline const char *get_progname(void)
{
	return __progname;
}
#endif
