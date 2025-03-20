#include <arch.h>
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
static struct pn_state pn_states[MAX_AUX_PLANES][MAX_RECS];

static void init_aux_plane_sysregs(struct sysreg_state *sysregs)
{
  sysregs->pmcr_el0 = PMCR_EL0_INIT;
  sysregs->sctlr_el1 = SCTLR_EL1_FLAGS;
  sysregs->mdscr_el1 = MDSCR_EL1_TDCC_BIT;

  gic_cpu_state_init(&sysregs->gicstate);
}

static struct pn_state *get_current_rec_pn_state(struct rec *rec)
{
  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  panic_if(p0_state->current_plane_index == 0, "Not in aux plane");

  return &pn_states[PLANE_TO_ARRAY(p0_state->current_plane_index)][rec_idx];
}

static struct p0_state *get_current_rec_p0_state(struct rec *rec)
{
  unsigned long rec_idx;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");

  return &p0_states[rec_idx];
}

void init_aux_plane_state(unsigned int num_aux_plane)
{
  panic_if(num_aux_plane > MAX_AUX_PLANES, "Number of aux planes out of range");

  for (unsigned int i = 0; i < num_aux_plane; i++) {
    for (unsigned int j = 0; j < MAX_RECS; j++) {
      pn_states[i][j].pstate = SPSR_EL2_MODE_EL1h
                                | SPSR_EL2_nRW_AARCH64
                                | SPSR_EL2_F_BIT
                                | SPSR_EL2_I_BIT
                                | SPSR_EL2_A_BIT
                                | SPSR_EL2_D_BIT;

      init_aux_plane_sysregs(&pn_states[i][j].sysregs);
    }
  }
}

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
  INFO("[Plane]\tLoading sysregs\n");

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
  INFO("[Plane]\tSaving sysregs\n");

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

static void load_aux_state(struct rec *rec, struct rsi_plane_enter *enter, struct pn_state *pn_state)
{
  INFO("[Plane]\tLoading aux state\n");
  pn_state->flags = enter->flags;

  /* Load sysregs from realm descriptor */
  load_sysregs(&pn_state->sysregs);
  write_spsr_el2(pn_state->pstate);

  /* Load common states from plane run enter */
  INFO("[Plane]\tLoading Pn's PC = 0x%016lx\n", enter->pc);
  write_elr_el2(enter->pc);
  for (int i = 0; i < PLANE_EXIT_NR_GPRS; i++) {
    rec->regs[i] = enter->gprs[i];
  }

  /* Load GIC info from plane run enter */
  if ((enter->flags & PLANE_ENTER_FLAG_GIC_OWNER) != 0) {
    pn_state->sysregs.gicstate.ich_hcr_el2 = enter->gicv3_hcr;
    memcpy(pn_state->sysregs.gicstate.ich_lr_el2, enter->gicv3_lrs, sizeof(enter->gicv3_lrs));
  }
  gic_restore_state(&pn_state->sysregs.gicstate);
}

static void save_aux_state(struct rec *rec, struct rsi_plane_exit *exit, struct pn_state *pn_state)
{
  INFO("[Plane]\tSaving aux state\n");
  pn_state->flags = 0;

  /* Save sysregs to realm descriptor */
  save_sysregs(&pn_state->sysregs);
  pn_state->pstate = read_spsr_el2();

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
  gic_save_state(&pn_state->sysregs.gicstate);
  exit->gicv3_hcr = pn_state->sysregs.gicstate.ich_hcr_el2;
  memcpy(exit->gicv3_lrs, pn_state->sysregs.gicstate.ich_lr_el2, sizeof(exit->gicv3_lrs));
  exit->gicv3_misr = pn_state->sysregs.gicstate.ich_misr_el2;
  exit->gicv3_vmcr = pn_state->sysregs.gicstate.ich_vmcr_el2;
  write_ich_hcr_el2(pn_state->sysregs.gicstate.ich_hcr_el2 | ICH_HCR_EL2_EN_BIT); /* (Issue: gic_save_state) */

  /* Report Pn's timer state */
  exit->cntp_ctl = pn_state->sysregs.cntp_ctl_el0;
  exit->cntp_cval = pn_state->sysregs.cntp_cval_el0;
  exit->cntv_ctl = pn_state->sysregs.cntv_ctl_el0;
  exit->cntv_cval = pn_state->sysregs.cntv_cval_el0;
}

static void load_p0_state(struct rec *rec)
{
  INFO("[Plane]\tLoading P0 state\n");

  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  /* Load P0's common state */
  write_elr_el2(p0_state->pc);
  write_spsr_el2(p0_state->pstate);
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
  INFO("[Plane]\tSaving P0 state\n");

  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  /* Save P0's common state */
  p0_state->pc = read_elr_el2() + 4UL;
  p0_state->pstate = read_spsr_el2();
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
  INFO("[Plane]\tExiting aux plane\n");

  struct p0_state *p0_state;
  unsigned long plane_run_pa;
  struct rd *rd;
  struct rsi_plane_run *run;

  p0_state = get_current_rec_p0_state(rec);

  plane_run_pa = p0_state->plane_run_pa;
  panic_if(plane_run_pa == 0, "Invalid plane run PA");
  run = (struct rsi_plane_run *)buffer_granule_map(find_granule(plane_run_pa), SLOT_RSI_CALL);

  rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);

  /* Switch back to P0 */
  run->exit.exit_reason = exit_reason;
  save_aux_state(rec, &run->exit, get_current_rec_pn_state(rec));
  load_p0_state(rec);
  rec->gic_owner = 0;

  /* Unmap rd granule and PlaneRun granule */
  buffer_unmap(rd);
  buffer_unmap(run);
}

void check_plane_exit(struct rec *rec)
{
  INFO("[Plane]\tChecking plane exit\n");

  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  p0_state = get_current_rec_p0_state(rec);

  panic_if(p0_state->current_plane_index == 0, "Not in aux plane");

  /*
   * Check Plane Exit caused by Interrupt
   */
  if (rec->gic_owner != p0_state->current_plane_index
      && rec->sysregs.gicstate.ich_misr_el2 != 0) {
    INFO("[Plane]\tREC %lu is in aux plane %lu, GIC owner %lu, GIC MISR 0x%lx\n",
         rec_idx, p0_state->current_plane_index, rec->gic_owner, rec->sysregs.gicstate.ich_misr_el2);
    exit_aux_plane(rec, RSI_EXIT_IRQ);
    INFO("[Plane]\tExit from aux plane\n");
  }

  /*
   * TODO: Check Plane Exit caused by Host Action
   */

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

static bool check_rec_exit(struct rec *rec, struct rmi_rec_exit *rec_exit, unsigned long exit_reason)
{
  /* IRQ / FIQ / SError cause REC Exit */
  if (exit_reason == ARM_EXCEPTION_IRQ_LEL) {
    rec_exit->exit_reason = RMI_EXIT_IRQ;
    return true;
  }

  if (exit_reason == ARM_EXCEPTION_FIQ_LEL) {
    rec_exit->exit_reason = RMI_EXIT_FIQ;
    return true;
  }

  if (exit_reason == ARM_EXCEPTION_SERROR_LEL) {
    rec_exit->exit_reason = RMI_EXIT_SERROR;
    rec->last_run_info.esr = read_esr_el2();
    rec->last_run_info.far = read_far_el2();
    rec->last_run_info.hpfar = read_hpfar_el2();
    return true;
  }

  if (exit_reason == ARM_EXCEPTION_SYNC_LEL) {
    unsigned long esr = read_esr_el2();
    unsigned long esr_ec = esr & MASK(ESR_EL2_EC);

    /*
     * If RIPAS is DESTROYED, or HIPAS is UNASSIGNED and RIPAS is not EMPTY,
     * cause REC Exit
     */
    if (esr_ec == ESR_EL2_EC_INST_ABORT ||
        esr_ec == ESR_EL2_EC_DATA_ABORT ||
        esr_ec == ESR_EL2_EC_INST_ABORT_SEL ||
        esr_ec == ESR_EL2_EC_DATA_ABORT_SEL) {
      unsigned long hpfar = read_hpfar_el2();
      unsigned long fipa = (hpfar & MASK(HPFAR_EL2_FIPA)) << HPFAR_EL2_FIPA_OFFSET;

      struct s2tt_context *s2_ctx;
      struct s2tt_walk wi;
      unsigned long s2tte, *ll_table;

      s2_ctx = &(rec->realm_info.s2_ctx);
      granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

      s2tt_walk_lock_unlock(s2_ctx, fipa, S2TT_PAGE_LEVEL, &wi);

      ll_table = buffer_granule_map(wi.g_llt, SLOT_RTT);
      s2tte = s2tte_read(&ll_table[wi.index]);

      granule_unlock(wi.g_llt);
      buffer_unmap(ll_table);

      unsigned long ripas_val;
      unsigned long hipas_val;

      ripas_val = s2tte_get_ripas(s2_ctx, s2tte);
      hipas_val = s2tte_get_hipas(s2_ctx, s2tte);

      /* RMM doesn't define HIPAS yet */
      if (ripas_val == RIPAS_DESTROYED ||
          (hipas_val == RMI_UNASSIGNED && ripas_val != RIPAS_EMPTY)) {
        rec_exit->exit_reason = RMI_EXIT_SYNC;
        rec_exit->esr = esr;
        rec_exit->far = read_far_el2();
        rec_exit->hpfar = hpfar;
        rec->last_run_info.esr = esr;
        rec->last_run_info.far = read_far_el2();

        return true;
      }
    }

    return false;
  }

  return false;
}

static bool check_aux_plane_sync_exception(struct rec *rec, unsigned long exit_reason)
{
  if (exit_reason != ARM_EXCEPTION_SYNC_LEL) {
    return false;
  }

  unsigned long esr = read_esr_el2();
  unsigned long esr_ec = esr & MASK(ESR_EL2_EC);

  /*
   * If WFX, cause Plane Exit
   */
  if (esr_ec == ESR_EL2_EC_WFX) {
    return true;
  }

  if (esr_ec == ESR_EL2_EC_INST_ABORT ||
      esr_ec == ESR_EL2_EC_DATA_ABORT ||
      esr_ec == ESR_EL2_EC_INST_ABORT_SEL ||
      esr_ec == ESR_EL2_EC_DATA_ABORT_SEL) {

    unsigned long hpfar = read_hpfar_el2();
    unsigned long fipa = (hpfar & MASK(HPFAR_EL2_FIPA)) << HPFAR_EL2_FIPA_OFFSET;

    struct s2tt_context *s2_ctx;
    struct s2tt_walk wi;
    unsigned long s2tte, *ll_table;

    s2_ctx = &(rec->realm_info.s2_ctx);
    granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

    s2tt_walk_lock_unlock(s2_ctx, fipa, S2TT_PAGE_LEVEL, &wi);
    ll_table = buffer_granule_map(wi.g_llt, SLOT_RTT);

    s2tte = s2tte_read(&ll_table[wi.index]);

    granule_unlock(wi.g_llt);
    buffer_unmap(ll_table);

    unsigned long ripas_val;

    ripas_val = s2tte_get_ripas(s2_ctx, s2tte);

    /*
     * If RIPAS is EMPTY, cause Plane Exit
     */
    if (ripas_val == RIPAS_EMPTY) {
      return true;
    }

    /*
     * TODO: Check permission fault of IPA
     */
  }

  /*
   * If HVC or SMC, cause Plane Exit
   */
  if (esr_ec == ESR_EL2_EC_HVC) {
    return true;
  }

  if (esr_ec == ESR_EL2_EC_SMC) {
    unsigned long fid = rec->regs[0];

    /*
     * If SMC is Host Call but not Trap Host Call, don't cause Plane Exit
     */
    if (fid == SMC_RSI_HOST_CALL && (get_current_rec_pn_state(rec)->flags & PLANE_ENTER_FLAG_TRAP_HC) == 0) {
      return false;
    }

    return true;
  }

  return false;
}

bool handle_aux_plane_exit(struct rec *rec, struct rmi_rec_exit *rec_exit, unsigned long exit_reason)
{
  INFO("[Plane]\tAn exception:\n"
      "elr_el2 = 0x%016lx\n"
      "esr_el2 = 0x%016lx\n"
      "far_el2 = 0x%016lx\n"
      "hpfar_el2 = 0x%016lx\n"
      "spsr_el2 = 0x%016lx\n",
      read_elr_el2(), read_esr_el2(), read_far_el2(), read_hpfar_el2(), read_spsr_el2());
  INFO("elr_el1 = 0x%016lx\n"
      "esr_el1 = 0x%016lx\n"
      "far_el1 = 0x%016lx\n"
      "spsr_el1 = 0x%016lx\n",
      read_elr_el12(), read_esr_el12(), read_far_el12(), read_spsr_el12());

  if (check_rec_exit(rec, rec_exit, exit_reason)) {
    INFO("[Plane]\tPn's exception needs to be handled by Host, causes REC Exit\n");
    return false;
  }

  unsigned long plane_exit_reason = RSI_EXIT_UNKNOWN;

  if (check_aux_plane_sync_exception(rec, exit_reason)) {
    INFO("[Plane]\tPn's sync exception\n");
    plane_exit_reason = RSI_EXIT_SYNC;
  }

  if (plane_exit_reason == RSI_EXIT_UNKNOWN) {
    INFO("[Plane]\tUndefined exception, exit to p0\n");
  }

  INFO("[Plane]\tPn's exception needs to be handled by P0, causes Plane Exit\n");
  exit_aux_plane(rec, plane_exit_reason);

  return true;
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
  load_aux_state(rec, &run->enter, &pn_states[PLANE_TO_ARRAY(plane_index)][rec->rec_idx]);
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
