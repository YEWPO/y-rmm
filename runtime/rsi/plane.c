#include <arch_helpers.h>
#include <debug.h>
#include <buffer.h>
#include <realm.h>
#include <plane.h>
#include <granule.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <stdbool.h>
#include <exit.h>

static struct p0_state p0_states[MAX_RECS];

bool is_aux_plane(struct rec *rec)
{
  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  return (p0_state->current_plane_index != 0);
}

static void load_sysregs(STRUCT_TYPE sysreg_state *sysregs)
{
  INFO("[Plane]\tLoading sysregs, sysregs = 0x%p\n", sysregs);

  write_sp_el0(sysregs->sp_el0);
  write_sp_el1(sysregs->sp_el1);
  write_elr_el12(sysregs->elr_el1);
  write_spsr_el12(sysregs->spsr_el1);
  write_pmcr_el0(sysregs->pmcr_el0);
  write_tpidrro_el0(sysregs->tpidrro_el0);
  write_tpidr_el0(sysregs->tpidr_el0);
  write_csselr_el1(sysregs->csselr_el1);
  write_sctlr_el12(sysregs->sctlr_el1);
  write_sctlr2_el12_if_present(sysregs->sctlr2_el1);
  write_actlr_el1(sysregs->actlr_el1);
  write_cpacr_el12(sysregs->cpacr_el1);
  write_ttbr0_el12(sysregs->ttbr0_el1);
  write_ttbr1_el12(sysregs->ttbr1_el1);
  write_tcr_el12(sysregs->tcr_el1);
  write_esr_el12(sysregs->esr_el1);
  write_afsr0_el12(sysregs->afsr0_el1);
  write_afsr1_el12(sysregs->afsr1_el1);
  write_far_el12(sysregs->far_el1);
  write_mair_el12(sysregs->mair_el1);
  write_vbar_el12(sysregs->vbar_el1);

  write_contextidr_el12(sysregs->contextidr_el1);
  write_tpidr_el1(sysregs->tpidr_el1);
  write_amair_el12(sysregs->amair_el1);
  write_cntkctl_el12(sysregs->cntkctl_el1);
  write_par_el1(sysregs->par_el1);
  write_mdscr_el1(sysregs->mdscr_el1);
  write_mdccint_el1(sysregs->mdccint_el1);
  write_disr_el1(sysregs->disr_el1);
  MPAM(write_mpam0_el1(sysregs->mpam0_el1);)

  write_cntp_ctl_el02(sysregs->cntp_ctl_el0);
  write_cntp_cval_el02(sysregs->cntp_cval_el0);
  write_cntv_ctl_el02(sysregs->cntv_ctl_el0);
  write_cntv_cval_el02(sysregs->cntv_cval_el0);
}

static void save_sysregs(STRUCT_TYPE sysreg_state *sysregs)
{
  INFO("[Plane]\tSaving sysregs, sysregs = 0x%p\n", sysregs);

  sysregs->sp_el0 = read_sp_el0();
  sysregs->sp_el1 = read_sp_el1();
  sysregs->elr_el1 = read_elr_el12();
  sysregs->spsr_el1 = read_spsr_el12();
  sysregs->pmcr_el0 = read_pmcr_el0();
  sysregs->tpidrro_el0 = read_tpidrro_el0();
  sysregs->tpidr_el0 = read_tpidr_el0();
  sysregs->csselr_el1 = read_csselr_el1();
  sysregs->sctlr_el1 = read_sctlr_el12();
  sysregs->sctlr2_el1 = read_sctlr2_el12_if_present();
  sysregs->actlr_el1 = read_actlr_el1();
  sysregs->cpacr_el1 = read_cpacr_el12();
  sysregs->ttbr0_el1 = read_ttbr0_el12();
  sysregs->ttbr1_el1 = read_ttbr1_el12();
  sysregs->tcr_el1 = read_tcr_el12();
  sysregs->esr_el1 = read_esr_el12();
  sysregs->afsr0_el1 = read_afsr0_el12();
  sysregs->afsr1_el1 = read_afsr1_el12();
  sysregs->far_el1 = read_far_el12();
  sysregs->mair_el1 = read_mair_el12();
  sysregs->vbar_el1 = read_vbar_el12();

  sysregs->contextidr_el1 = read_contextidr_el12();
  sysregs->tpidr_el1 = read_tpidr_el1();
  sysregs->amair_el1 = read_amair_el12();
  sysregs->cntkctl_el1 = read_cntkctl_el12();
  sysregs->par_el1 = read_par_el1();
  sysregs->mdscr_el1 = read_mdscr_el1();
  sysregs->mdccint_el1 = read_mdccint_el1();
  sysregs->disr_el1 = read_disr_el1();
  MPAM(sysregs->mpam0_el1 = read_mpam0_el1();)

  sysregs->cntp_ctl_el0 = read_cntp_ctl_el02();
  sysregs->cntp_cval_el0 = read_cntp_cval_el02();
  sysregs->cntv_ctl_el0 = read_cntv_ctl_el02();
  sysregs->cntv_cval_el0 = read_cntv_cval_el02();
}

static void load_aux_state(struct rec *rec, struct rsi_plane_enter *enter, STRUCT_TYPE sysreg_state *sysregs)
{
  INFO("[Plane]\tLoading aux state, rec = 0x%p, enter = 0x%p\n", rec, enter);

  /* Load sysregs from realm descriptor */
  load_sysregs(sysregs);

  /* Load common states from plane run enter */
  write_elr_el2(enter->pc);
  for (int i = 0; i < PLANE_EXIT_NR_GPRS; i++) {
    rec->regs[i] = enter->gprs[i];
  }

  /* Load GIC info from plane run enter */
  if ((enter->flags & PLANE_ENTER_FLAG_GIC_OWNER) != 0) {
    sysregs->gicstate.ich_hcr_el2 = enter->gicv3_hcr;
    memcpy(sysregs->gicstate.ich_lr_el2, enter->gicv3_lrs, sizeof(enter->gicv3_lrs));
  }
  gic_restore_state(&sysregs->gicstate);
}

static void save_aux_state(struct rec *rec, struct rsi_plane_exit *exit, STRUCT_TYPE sysreg_state *sysregs)
{
  INFO("[Plane]\tSaving aux state, rec = 0x%p, exit = 0x%p\n", rec, exit);

  /* Save sysregs to realm descriptor */
  save_sysregs(sysregs);

  /* Save common states to plane run exit */
  for (int i = 0; i < PLANE_EXIT_NR_GPRS; i++) {
    exit->gprs[i] = rec->regs[i];
  }

  /* Save exception info to plane run exit */
  exit->elr_el2 = read_elr_el2();
  exit->esr_el2 = read_esr_el2();
  exit->far_el2 = read_far_el2();
  exit->hpfar_el2 = read_hpfar_el2();

  /* Report Pn's GIC info */
  gic_save_state(&sysregs->gicstate);
  exit->gicv3_hcr = sysregs->gicstate.ich_hcr_el2;
  memcpy(exit->gicv3_lrs, sysregs->gicstate.ich_lr_el2, sizeof(exit->gicv3_lrs));
  exit->gicv3_misr = sysregs->gicstate.ich_misr_el2;
  exit->gicv3_vmcr = sysregs->gicstate.ich_vmcr_el2;
  write_ich_hcr_el2(sysregs->gicstate.ich_hcr_el2 | ICH_HCR_EL2_EN_BIT); /* (Issue: gic_save_state) */

  /* Report Pn's timer state */
  exit->cntp_ctl = sysregs->cntp_ctl_el0;
  exit->cntp_cval = sysregs->cntp_cval_el0;
  exit->cntv_ctl = sysregs->cntv_ctl_el0;
  exit->cntv_cval = sysregs->cntv_cval_el0;
}

static void load_p0_state(struct rec *rec)
{
  INFO("[Plane]\tLoading P0 state, rec = 0x%p\n", rec);

  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  /* Load P0's common state */
  write_elr_el2(p0_state->pc);
  for (int i = 0; i < PLANE_EXIT_NR_GPRS; i++) {
    rec->regs[i] = p0_state->gprs[i];
  }

  /* Clear Pn's related info */
  p0_state->current_plane_index = 0;
  p0_state->plane_run_pa = 0;

  /* Load P0's sysregs */
  load_sysregs(&p0_state->sysregs);
}

static void save_p0_state(struct rec *rec, unsigned long plane_index, unsigned long plane_run_pa)
{
  INFO("[Plane]\tSaving P0 state, rec = 0x%p, plane_index = %lu, plane_run_pa = 0x%lx\n", rec, plane_index, plane_run_pa);

  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  /* Save P0's common state */
  p0_state->pc = read_elr_el2() + 4UL;
  for (int i = 0; i < PLANE_EXIT_NR_GPRS; i++) {
    p0_state->gprs[i] = rec->regs[i];
  }

  /* Save Pn's related info */
  p0_state->current_plane_index = plane_index;
  p0_state->plane_run_pa = plane_run_pa;

  /* Save P0's sysregs */
  save_sysregs(&p0_state->sysregs);
}

static void exit_aux_plane(struct rec *rec, unsigned long exit_reason)
{
  INFO("[Plane]\tExiting aux plane, rec = 0x%p\n", rec);

  unsigned long rec_idx;
  struct p0_state *p0_state;
  unsigned long aux_plane_index;
  unsigned long plane_run_pa;
  struct rd *rd;
  struct rsi_plane_run *run;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  aux_plane_index = p0_state->current_plane_index;
  panic_if(aux_plane_index == 0, "Not in aux plane");
  plane_run_pa = p0_state->plane_run_pa;
  panic_if(plane_run_pa == 0, "Invalid plane run PA");
  run = (struct rsi_plane_run *)buffer_granule_map(find_granule(plane_run_pa), SLOT_RSI_CALL);

  rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);

  /* Switch back to P0 */
  run->exit.exit_reason = exit_reason;
  save_aux_state(rec, &run->exit, &rd->sysregs[PLANE_TO_ARRAY(aux_plane_index)]);
  load_p0_state(rec);
  rec->gic_owner = 0;

  /* Unmap rd granule and PlaneRun granule */
  buffer_unmap(rd);
  buffer_unmap(run);
}

void check_plane_exit(struct rec *rec)
{
  INFO("[Plane]\tChecking plane exit, rec = 0x%p\n", rec);

  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  panic_if(p0_state->current_plane_index == 0, "Not in aux plane");

  if (rec->gic_owner != p0_state->current_plane_index
      && rec->sysregs.gicstate.ich_misr_el2 != 0) {
    INFO("[Plane]\tREC %lu is in aux plane %lu, GIC owner %lu, GIC MISR 0x%lx\n",
         rec_idx, p0_state->current_plane_index, rec->gic_owner, rec->sysregs.gicstate.ich_misr_el2);
    exit_aux_plane(rec, RSI_EXIT_IRQ);
    INFO("[Plane]\tExit from aux plane\n");
  }

  INFO("[Plane]\tKeep running in current plane\n");
}

struct gic_cpu_state *get_gic_owner_gic_state(struct rec *rec)
{
  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  panic_if(p0_state->current_plane_index == 0 && rec->gic_owner != 0, "Invalid GIC owner");
  if ((p0_state->current_plane_index ^ rec->gic_owner) != 0) {
    return &p0_state->sysregs.gicstate;
  }

  return &rec->sysregs.gicstate;
}

void report_plane_timer_state(struct rec *rec, struct timer_state *timer_state)
{
  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  /* REC Exit from P0 */
  if (p0_state->current_plane_index == 0) {
    timer_state->cntv_ctl = read_cntv_ctl_el02();
    timer_state->cntv_cval = read_cntv_cval_el02() - read_cntvoff_el2();
    timer_state->cntp_ctl = read_cntp_ctl_el02();
    timer_state->cntp_cval = read_cntp_cval_el02() - read_cntpoff_el2();
    return;
  }

  INFO("[Plane]\tReporting plane timer state, rec = 0x%p\n", rec);

  /* REC Exit from Pn */
  unsigned long p0_cntv_ctl, p0_cntv_cval, p0_cntp_ctl, p0_cntp_cval;
  unsigned long pn_cntv_ctl, pn_cntv_cval, pn_cntp_ctl, pn_cntp_cval;
  bool p0_cntv_active, p0_cntp_active, pn_cntv_active, pn_cntp_active;

  p0_cntp_ctl = p0_state->sysregs.cntp_ctl_el0;
  p0_cntp_cval = p0_state->sysregs.cntp_cval_el0 - p0_state->sysregs.cntpoff_el2;
  p0_cntv_ctl = p0_state->sysregs.cntv_ctl_el0;
  p0_cntv_cval = p0_state->sysregs.cntv_cval_el0 - p0_state->sysregs.cntvoff_el2;
  pn_cntp_ctl = read_cntp_ctl_el02();
  pn_cntp_cval = read_cntp_cval_el02() - read_cntpoff_el2();
  pn_cntv_ctl = read_cntv_ctl_el02();
  pn_cntv_cval = read_cntv_cval_el02() - read_cntvoff_el2();

#define TIMER_ACTIVE(ctl) (((ctl) & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK)) == CNTx_CTL_ENABLE)

  p0_cntv_active = TIMER_ACTIVE(p0_cntv_ctl);
  p0_cntp_active = TIMER_ACTIVE(p0_cntp_ctl);
  pn_cntv_active = TIMER_ACTIVE(pn_cntv_ctl);
  pn_cntp_active = TIMER_ACTIVE(pn_cntp_ctl);

  if ((pn_cntv_active && !p0_cntv_active)
      || (pn_cntv_active && p0_cntv_active && (pn_cntv_cval < p0_cntv_cval))) {
    INFO("[Plane]\tReport Pn's CNTV\n");
    timer_state->cntv_ctl = pn_cntv_ctl;
    timer_state->cntv_cval = pn_cntv_cval;
  } else {
    INFO("[Plane]\tReport P0's CNTV\n");
    timer_state->cntv_ctl = p0_cntv_ctl;
    timer_state->cntv_cval = p0_cntv_cval;
  }

  if ((pn_cntp_active && !p0_cntp_active)
      || (pn_cntp_active && p0_cntp_active && (pn_cntp_cval < p0_cntp_cval))) {
    INFO("[Plane]\tReport Pn's CNTP\n");
    timer_state->cntp_ctl = pn_cntp_ctl;
    timer_state->cntp_cval = pn_cntp_cval;
  } else {
    INFO("[Plane]\tReport P0's CNTP\n");
    timer_state->cntp_ctl = p0_cntp_ctl;
    timer_state->cntp_cval = p0_cntp_cval;
  }
}

static bool handle_aux_plane_sync_exception(struct rec *rec, struct rmi_rec_exit *rec_exit)
{
  unsigned long esr = read_esr_el2();
  unsigned long esr_ec = esr & MASK(ESR_EL2_EC);

  if (esr_ec == ESR_EL2_EC_SMC) {
    /*
     * TODO: Check whether it is a host_call
     */
  }

  if (esr_ec == ESR_EL2_EC_DATA_ABORT || esr_ec == ESR_EL2_EC_INST_ABORT) {
    if (handle_sync_external_abort(rec, rec_exit, esr)) {
      INFO("[Plane]\tHandled SEA\n");
      return false;
    }

    unsigned long hpfar = read_hpfar_el2();
    unsigned long fipa = (hpfar & MASK(HPFAR_EL2_FIPA)) << HPFAR_EL2_FIPA_OFFSET;

    /* Walk for RIPAS */
    struct s2_walk_result walk_res;
    enum s2_walk_status walk_status;

    walk_status = realm_ipa_to_pa(rec, fipa, &walk_res);
    panic_if(walk_status == WALK_INVALID_PARAMS, "handle aux plane sync exception should not reach here");

    if (walk_status == WALK_SUCCESS) {
      granule_unlock(walk_res.llt);
    }

    /*
     * Walk for HIPAS
     */
    struct s2tt_walk wi;
    struct s2tt_context *s2_ctx = &rec->realm_info.s2_ctx;
    unsigned long *ll_table, s2tte;

    granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);
    s2tt_walk_lock_unlock(s2_ctx, fipa, S2TT_PAGE_LEVEL, &wi);

    ll_table = buffer_granule_map(wi.g_llt, SLOT_RTT);
    assert(ll_table != NULL);

    s2tte = s2tte_read(&ll_table[wi.index]);

    buffer_unmap(ll_table);
    granule_unlock(wi.g_llt);

    /*
     * if RIPAS is DESTROYED, cause REC Exit
     */
    if (walk_res.ripas_val == RIPAS_DESTROYED) {
      goto rec_exit;
    }

    /*
     * if HIPAS is UNASSIGNED and RIPAS is not EMPTY, cause REC Exit
     */
    if (s2tte_is_unassigned(s2_ctx, s2tte) && walk_res.ripas_val != RIPAS_EMPTY) {
      goto rec_exit;
    }
  }

  /*
   * Any other sync exception, cause Plane Exit
   */
  exit_aux_plane(rec, RSI_EXIT_SYNC);
  return true;

rec_exit:
  rec_exit->exit_reason = RMI_EXIT_SYNC;
  rec_exit->esr = esr & ESR_NONEMULATED_ABORT_MASK;
  rec_exit->far = read_far_el2();
  rec_exit->hpfar = read_hpfar_el2();
  return false;
}

bool handle_aux_plane_exit(struct rec *rec, struct rmi_rec_exit *rec_exit, unsigned long exit_reason)
{
  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  panic_if(p0_state->current_plane_index == 0, "Not in aux plane");

  INFO("[Plane]\tAn exception:\n"
      "elr = 0x%016lx\n"
      "esr = 0x%016lx\n"
      "far = 0x%016lx\n"
      "hpfar = 0x%016lx\n",
      read_elr_el2(), read_esr_el2(), read_far_el2(), read_hpfar_el2());

  switch (exit_reason) {
    case ARM_EXCEPTION_SYNC_LEL:
      return handle_aux_plane_sync_exception(rec, rec_exit);
    case ARM_EXCEPTION_IRQ_LEL:
      rec_exit->exit_reason = RMI_EXIT_IRQ;
      return false;
    case ARM_EXCEPTION_FIQ_LEL:
      rec_exit->exit_reason = RMI_EXIT_FIQ;
      return false;
    case ARM_EXCEPTION_SERROR_LEL:
      rec_exit->exit_reason = RMI_EXIT_SERROR;
      return false;
    default:
      INFO("[Plane]\tUnrecognized exit reason: %lu\n", exit_reason);
      panic();
  }
}

void handle_rsi_plane_enter(struct rec *rec, struct rsi_result *res)
{
  unsigned long plane_index = rec->regs[1];
  unsigned long ipa = rec->regs[2];

  enum s2_walk_status walk_status;
  struct s2_walk_result walk_res;
  struct granule *gr;
  struct rsi_plane_run *run;
  struct rd *rd;

  res->action = UPDATE_REC_RETURN_TO_REALM;

  rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);

  /* Check plane index boundary */
  if (plane_index < 1 || plane_index > rd->num_aux_planes) {
    res->smc_res.x[0] = RSI_ERROR_INPUT;
    return;
  }

  /* Check ipa alignment and boundary */
  if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
    res->smc_res.x[0] = RSI_ERROR_INPUT;
    return;
  }

  /* Walk IPA */
  walk_status = realm_ipa_to_pa(rec, ipa, &walk_res);

  if (walk_status == WALK_FAIL) {
    if (walk_res.ripas_val == RIPAS_EMPTY) {
      res->smc_res.x[0] = RSI_ERROR_INPUT;
    } else {
      res->action = STAGE_2_TRANSLATION_FAULT;
      res->rtt_level = walk_res.rtt_level;
    }
    return;
  }

  if (walk_status == WALK_INVALID_PARAMS) {
    res->smc_res.x[0] = RSI_ERROR_INPUT;
    return;
  }

  /* Map plane run granule to RMM address space */
  gr = find_granule(walk_res.pa);
  run = (struct rsi_plane_run *)buffer_granule_map(gr, SLOT_RSI_CALL);
  assert(run != NULL);

  /* Switch to aux plane */
  save_p0_state(rec, plane_index, walk_res.pa);
  load_aux_state(rec, &run->enter, &rd->sysregs[PLANE_TO_ARRAY(plane_index)]);
  if ((run->enter.flags & PLANE_ENTER_FLAG_GIC_OWNER) != 0) {
    rec->gic_owner = plane_index;
  }

  /* Unmap rd granule and PlaneRun granule */
  buffer_unmap(rd);
  buffer_unmap(run);

  /* Unlock last level RTT */
  granule_unlock(walk_res.llt);

  /* Write result values */
  res->smc_res.x[0] = RSI_SUCCESS;
}
