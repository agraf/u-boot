/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Duncan Hare Copyright 2017
 */

void wget_start(void);			/* Begin wget */

enum WGET_STATE {
	WGET_CLOSED,
	WGET_CONNECTING,
	WGET_CONNECTED,
	WGET_TRANSFERRING,
	WGET_TRANSFERRED
};

#define	DEBUG_WGET		0	/* Set to 1 for debug messges */
#define	SERVER_PORT		80
#define	WGET_RETRY_COUNT	30
#define	WGET_TIMEOUT		2000UL
