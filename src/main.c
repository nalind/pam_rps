/*
   Copyright (c) 2003,2010 Red Hat, Inc.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

   * Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

   * Neither the name of Red Hat, Inc., nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

static int
converse(int n, const struct pam_message **msgs,
	 struct pam_response **resp, void *p)
{
	const struct pam_message *msg;
	char buf[LINE_MAX], *s;
	int i;
	if (n > 1) {
		printf("Best of %d:\n", n);
	}
	*resp = malloc(sizeof(struct pam_response) * n);
	if (*resp == NULL) {
		return PAM_BUF_ERR;
	}
	memset(*resp, 0, sizeof(resp[0]) * n);
	for (i = 0; i < n; i++) {
		if (p != NULL) {
			/* Linux-PAM ABI. */
			msg = &((*msgs)[i]);
		} else {
			/* Sun ABI. */
			msg = msgs[i];
		}
		switch (msg->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			s = getpass(msg->msg);
			if (s == NULL) {
				s = "";
			}
			(*resp)[i].resp_retcode = 0;
			(*resp)[i].resp = strdup(s);
			break;
		case PAM_PROMPT_ECHO_ON:
			fprintf(stderr, "%s", msg->msg);
			s = fgets(buf, sizeof(buf), stdin);
			if (s == NULL) {
				s = "";
			}
			s[strcspn(s, "\r\n")] = '\0';
			(*resp)[i].resp_retcode = 0;
			(*resp)[i].resp = strdup(s);
			break;
		default:
			fprintf(stderr, "%s\n", msg->msg);
			(*resp)[i].resp_retcode = 0;
			(*resp)[i].resp = NULL;
			break;
		}
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int i;
	pam_handle_t *pamh;
	struct pam_conv conv = {
		.conv = converse,
		.appdata_ptr = &conv,
	};
	/* We'll use "is the appdata not NULL" to indicate Linux-style. */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "sun") == 0) {
			conv.appdata_ptr = NULL;
		}
		if (strcmp(argv[i], "linux") == 0) {
			conv.appdata_ptr = &conv;
		}
	}
	/* Start up PAM.  We're not going to use it, though. */
	i = pam_start("login", NULL, &conv, &pamh);
	if (i != PAM_SUCCESS) {
		printf("error starting PAM\n");
		return i;
	}
	/* Call our authentication function directly. */
	i = pam_sm_authenticate(pamh, 0, argc - 1, (const char **) (argv + 1));
	if (i != PAM_SUCCESS) {
		fprintf(stderr, "Error: %s\n", pam_strerror(pamh, i));
	} else {
		fprintf(stderr, "Succeeded.\n");
	}
	/* And we're done. */
	pam_end(pamh, i);
	return i;
}
