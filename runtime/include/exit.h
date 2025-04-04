/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef EXIT_H
#define EXIT_H

#include <stdbool.h>

struct rec;
struct rmi_rec_exit;

bool handle_realm_exit(struct rec *rec, struct rmi_rec_exit *rec_exit, int exception);
bool handle_sync_external_abort(struct rec *rec, struct rmi_rec_exit *rec_exit, unsigned long esr);

#endif /* EXIT_H */
