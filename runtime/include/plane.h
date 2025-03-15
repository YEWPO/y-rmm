#ifndef PLANE_H
#define PLANE_H

#include <stdbool.h>
#include <rec.h>
#include <timers.h>

/* Undetermined */
#define MAX_RECS              4U

#define MAX_AUX_PLANES        3U

#define PLANE_TO_ARRAY(plane) ((plane) - 1)
#define ARRAY_TO_PLANE(array) ((array) + 1)

struct p0_state {
  STRUCT_TYPE sysreg_state sysregs;

  unsigned long pc;
  unsigned long gprs[PLANE_EXIT_NR_GPRS];

  unsigned long current_plane_index;
  unsigned long plane_run_pa;
};

bool is_aux_plane(struct rec *rec);
void exit_aux_plane(struct rec *rec, unsigned long exit_reason);
void check_plane_exit(struct rec *rec);
struct gic_cpu_state *get_gic_owner_gic_state(struct rec *rec);
void report_plane_timer_state(struct rec *rec, struct timer_state *timer_state);
bool handle_aux_plane_exit(struct rec *rec, struct rmi_rec_exit *rec_exit, unsigned long exit_reason);

#endif
