/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Access vector cache interface for the security server.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */
#ifndef _SELINUX_AVC_SS_H_
#define _SELINUX_AVC_SS_H_

#include "flask.h"

<<<<<<< HEAD
struct selinux_avc;
int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
=======
int avc_ss_reset(u32 seqno);
>>>>>>> v4.14.187

/* Class/perm mapping support */
struct security_class_mapping {
	const char *name;
	const char *perms[sizeof(u32) * 8 + 1];
};

extern struct security_class_mapping secclass_map[];

<<<<<<< HEAD
extern int ss_initialized; // SEC_SELINUX_PORTING_COMMON
=======
/*
 * The security server must be initialized before
 * any labeling or access decisions can be provided.
 */
extern int ss_initialized;
>>>>>>> v4.14.187

#endif /* _SELINUX_AVC_SS_H_ */

