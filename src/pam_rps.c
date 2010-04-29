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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_modules.h>

/* These are the rules. */
struct beater {
	const char *what, *how;
};
struct beater what_beats_rock[] = {
	{"paper", "covers"},
};
struct beater what_beats_paper[] = {
	{"scissors", "cuts"},
};
struct beater what_beats_scissors[] = {
	{"rock", "blunts"},
};
struct rule {
	const char *challenge;
	struct beater *beaters;
};
struct rule rules[] = {
	{"rock: ", what_beats_rock},
	{"paper: ", what_beats_paper},
	{"scissors: ", what_beats_scissors},
};

/* Wrappers for pam_get_item() to get some measure of type-safety. */
static int
get_text_item(pam_handle_t *pamh, int item, const char **value)
{
	return pam_get_item(pamh, item, (const void **) value);
}

static int
get_conv_item(pam_handle_t *pamh, const struct pam_conv **value)
{
	return pam_get_item(pamh, PAM_CONV, (const void **) value);
}

/* Read a random byte, or return zero. */
static int
get_random_byte(void)
{
	unsigned char c;
	int ret, fd;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
		c = 0;
		do {
			ret = read(fd, &c, 1);
		} while ( ((ret ==  1) && (c == 0xff)) ||
			  ((ret == -1) && (errno == EINTR)) );
		/* We exclude 0xff here to avoid a variation on
		 * Bleichenbacher's attack. */
		ret = c & 0xff;
		close(fd);
	} else {
		ret = 0;
	}
	return ret;
}

/* Select the challenge. */
static void
fill(struct pam_message *msg, int style, int n_rules)
{
	memset(msg, 0, sizeof(*msg));
	msg->msg_style = style;
	msg->msg = rules[get_random_byte() % n_rules].challenge;
}

static void
won(int loglevel, const char *challenge, struct beater *beater,
    const char *response)
{
	if (loglevel != 0) {
		syslog(loglevel, "%s %s %s", response, beater->how, challenge);
	}
}

static void
lost(int loglevel, const char *challenge, const char *response)
{
	if (loglevel != 0) {
		syslog(loglevel, "%s did not beat %s", response, challenge);
	}
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	const struct pam_conv *conv;
	struct pam_response *responses;
	struct pam_message **msgs, *msg_array, *prompt;
	const struct pam_message **cmsgs;
	const char *service;
	int debug = 0, loglevel, i, j, k, score, best_of, prompt_style;
	int abi_sun, abi_linux, n_rules, n_winners;

#ifdef LOG_AUTHPRIV
	loglevel = LOG_AUTHPRIV | LOG_NOTICE;
#else
	loglevel = LOG_AUTH | LOG_NOTICE;
#endif

	/* Retrieve the PAM items that we care about. */
	service = NULL;
	i = get_text_item(pamh, PAM_SERVICE, &service);
	if ((i != PAM_SUCCESS) || (service == NULL)) {
		/* We only want the service name for logging purposes, but an
		 * error retrieving it would indicate a pretty serious problem
		 * elsewhere. */
		syslog(loglevel, "error retrieving PAM service name: %s",
		       pam_strerror(pamh, i));
		return i;
	}

	conv = NULL;
	i = get_conv_item(pamh, &conv);
	if ((i != PAM_SUCCESS) || (conv == NULL)) {
		/* We *need* a conversation function. */
		syslog(loglevel,
		       "error retrieving PAM conversation callback: %s",
		       pam_strerror(pamh, i));
		return i;
	}

	/* Parse our debug flag. */
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
#ifdef LOG_AUTHPRIV
			debug = LOG_AUTHPRIV | LOG_NOTICE;
#else
			debug = LOG_AUTH | LOG_NOTICE;
#endif
		}
	}

	/* Parse our arguments. */
	prompt_style = PAM_PROMPT_ECHO_OFF;
	best_of = 1;
	abi_sun = 1;
	abi_linux = 1;
	n_rules = 3;
	n_winners = 1;
	for (i = 0; i < argc; i++) {
		/* Force Linux-PAM-style semantics. */
		if (strcmp(argv[i], "linux") == 0) {
			if (debug) {
				syslog(debug, "requiring Linux-PAM-style "
				       "conversation semantics");
			}
			abi_linux = 1;
			abi_sun = 0;
		}
		/* Force Sun-PAM-style semantics. */
		if (strcmp(argv[i], "sun") == 0) {
			if (debug) {
				syslog(debug, "requiring Sun-PAM-style "
				       "conversation semantics");
			}
			abi_linux = 0;
			abi_sun = 1;
		}
		/* Change the prompt style. */
		if (strcmp(argv[i], "echo") == 0) {
			if (debug) {
				syslog(debug,
				       "will allow echoing of responses");
			}
			prompt_style = PAM_PROMPT_ECHO_ON;
		}
		/* Change the number of challenges. */
		if (strncmp(argv[i], "bestof=", 7) == 0) {
			best_of = atol(argv[i] + 7);
			if ((best_of % 2) == 0) {
				best_of++;
			}
			if (debug) {
				syslog(debug,
				       "requiring best of %d matches", best_of);
			}
		}
	}

	/* Set up the PAM message structure.  We want to be able to exercise
	 * the conversation callback using either Linux-style or Sun-style
	 * semantics. */
	msgs = NULL;
	if (abi_sun) {
		/* We need to prepare an array of pointers. */
		msgs = malloc(sizeof(struct pam_message *) * best_of);
		if (msgs == NULL) {
			return PAM_BUF_ERR;
		}
		memset(msgs, 0, sizeof(struct pam_message *) * best_of);
	}
	msg_array = NULL;
	if (abi_linux) {
		/* We need to prepare an array. */
		msg_array = malloc(sizeof(struct pam_message) * best_of);
		if (msg_array == NULL) {
			return PAM_BUF_ERR;
		}
		memset(msg_array, 0, sizeof(struct pam_message) * best_of);
	}
	if (abi_linux && abi_sun) {
		/* Make the array of pointers point to the array, and fill the
		 * array. */
		for (i = 0; i < best_of; i++) {
			msgs[i] = &msg_array[i];
			fill(&msg_array[i], prompt_style, n_rules);
		}
	} else {
		if (abi_linux) {
			/* Set the pointer to the array, and fill the array. */
			msgs = &msg_array;
			for (i = 0; i < best_of; i++) {
				fill(&msg_array[i], prompt_style, n_rules);
			}
		}
		if (abi_sun) {
			/* Allocate space for the pointed-to items, and fill
			 * them out. */
			for (i = 0; i < best_of; i++) {
				msgs[i] = malloc(sizeof(struct pam_message));
				if (msgs[i] == NULL) {
					return PAM_BUF_ERR;
				}
				memset(msgs[i], 0, sizeof(struct pam_message));
				fill(msgs[i], prompt_style, n_rules);
			}
		}
	}

	/* Call the application-supplied conversation function and sanity-check
	 * the responses. */
	responses = NULL;
	cmsgs = (const struct pam_message **) msgs;
	i = (*(conv->conv))(best_of, cmsgs, &responses, conv->appdata_ptr);
	if ((i != PAM_SUCCESS) || (responses == NULL)) {
		syslog(loglevel, "conversation error: %s",
		       pam_strerror(pamh, i));
		return PAM_CONV_ERR;
	}
	for (i = 0; i < best_of; i++) {
		if (responses[i].resp == NULL) {
			syslog(loglevel, "conversation error: "
			       "response %d of %d was NULL",
			       i + 1, best_of + 1);
			return PAM_CONV_ERR;
		}
	}

	/* Check the answers. */
	score = 0;
	for (i = 0; i < best_of; i++) {
		prompt = NULL;
		if (abi_linux) {
			prompt = &msg_array[i];
		}
		if (abi_sun) {
			prompt = msgs[i];
		}
		if (prompt == NULL) {
			continue;
		}
		/* Find the matching challenge. */
		for (j = 0; j < n_rules; j++) {
			if (strcmp(prompt->msg, rules[j].challenge) == 0) {
				/* Walk the list of winning responses. */
				for (k = 0; k < n_winners; k++) {
					if (strcasecmp(rules[j].beaters[k].what,
						       responses[i].resp) == 0){
						won(debug,
						    prompt->msg,
						    &rules[j].beaters[k],
						    responses[i].resp);
						score++;
						break;
					}
				}
				/* If we ran out of winning responses, then the
				 * user lost. */
				if (k >= n_winners) {
					lost(debug,
					     rules[j].challenge,
					     responses[i].resp);
				}
				break;
			}
		}
	}

	/* Free the prompts. */
	if (abi_linux) {
		free(msg_array);
	}
	if (abi_sun) {
		if (!abi_linux) {
			for (i = 0; i < best_of; i++) {
				free(msgs[i]);
			}
		}
		free(msgs);
	}

	/* Free the responses. */
	for (i = 0; i < best_of; i++) {
		free(responses[i].resp);
	}
	free(responses);

	/* If the user won, then the user is authenticated. */
	if ((score * 2) > best_of) {
		return PAM_SUCCESS;
	} else {
		return PAM_AUTH_ERR;
	}
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
