/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef TIMERS_H
#define TIMERS_H

struct rec;
struct rmi_rec_exit;

struct timer_state {
  unsigned long cntv_ctl;
  unsigned long cntv_cval;
  unsigned long cntp_ctl;
  unsigned long cntp_cval;
};

bool check_pending_timers(struct rec *rec);
void report_timer_state_to_ns(struct rmi_rec_exit *rec_exit, struct timer_state *timer_state);

#endif /* TIMERS_H */
