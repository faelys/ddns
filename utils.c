/* utils.c - various small helper functions */

/*
 * Copyright (c) 2009, Natacha Porté
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils.h"

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


/* daemonize • daemonises the application (inspired from FreeBSD's daemon()) */
int
daemonize(void) {
	struct sigaction sa, old_sa;
	int ret_sa, ret, old_en;

	/* SIGHUP blocking */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	ret_sa = sigaction(SIGHUP, &sa, &old_sa);

	/* fork()ing */
	ret = fork();
	if (ret == -1) {
		log_m_fork();
		return -1; }
	else if (ret) exit(0);

	/* setsid() */
	ret = setsid();
	old_en = errno;

	/* SIGHUP restoration */
	if (ret_sa != -1) sigaction(SIGHUP, &old_sa, 0);

	/* return failure when setsid() fails */
	if (ret == -1) {
		errno = old_en;
		log_m_setsid();
		return -1; }
	log_m_daemon();
	return 0; }



/* get_mtime • stat() a file and returns its modification time */
time_t
get_mtime(const char *filename) {
	struct stat st;
	if (stat(filename, &st)) {
		log_m_stat(filename);
		return 0; }
	return st.st_mtime; }


/* set_user_root • chroot() and/or setuid()+setgid() */
int
set_user_root(const char *root, const char *user) {
	struct passwd *pw = 0;
	int i;

	/* getting user information */
	if (user) {
		i = 0;
		while (user[i] >= '0' && user[i] <= '9') i += 1;
		if (user[i])
			pw = getpwnam(user);
		else
			pw = getpwuid((uid_t)atoi(user));
		if (!pw) log_m_bad_user(user);
		endpwent();
		if (!pw) return -1; }

	/* changing root */
	if (root) {
		if (chroot(root) < 0) {
			log_m_chroot(root);
			return -1; }
		if (chdir("/") < 0) {
			log_m_chdir(root);
			return -1; } }

	/* actual user and group id change */
	if (user) {
		if (setgid(pw->pw_gid) < 0) {
			log_m_setgid(user);
			return -1; }
		if (setuid(pw->pw_uid) < 0) {
			log_m_setuid(user);
			return -1; } }
	return 0; }


/* pidfile_write • helper function that perform the actual pid write */
static void
pidfile_write(int fd, pid_t pid) {
	char c;
	if (pid < 10)
		c = '0' + pid;
	else  {
		c = '0' + pid % 10;
		pidfile_write(fd, pid / 10); }
	write(fd, &c, 1); }


/* pidfile • prints the process id into the given file */
int
pidfile(const char *filename) {
	int fd;
	pid_t p;
	char c;

	/* sanity checks */
	if (!filename) return -1;

	/* atomic file non-existence test and creation */
	fd = open(filename, O_WRONLY | O_CREAT | O_EXCL,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1 && errno != EEXIST) {
		log_m_pid_create(filename);
		return -1; }

	/* if everything went fine, write the pid and exit */
	if (fd != -1) {
		pidfile_write(fd, getpid());
		c = '\n';
		write(fd, &c, 1);
		close(fd);
		return 0; }

	/* trying to open the existing pidfile */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		log_m_pid_open(filename);
		return -1; }

	/* reading the pid */
	p = 0;
	while (read(fd, &c, 1) > 0)
		if (c >= '0' && c <= '9') p = p * 10 + c - '0';
	close(fd);
	if (!p) log_m_pid_invalid(filename);

	/* checking pid existence */
	if (kill(p, 0) == 0) {
		log_m_pid_exist(filename, p);
		return -1; }
	if (errno != ESRCH) {
		log_m_pid_kill(filename, p);
		return -1; }

	/* re-opening the file to reuse it */
	fd = open(filename, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		log_m_pid_trunc(filename);
		return -1; }
	pidfile_write(fd, getpid());
	c = '\n';
	write(fd, &c, 1);
	close(fd);
	return 0; }

/* vim: set filetype=c: */
