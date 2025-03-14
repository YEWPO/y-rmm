#include <debug.h>
#include <buffer.h>
#include <realm.h>
#include <plane.h>
#include <granule.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <stdbool.h>

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

  write_cntpoff_el2(sysregs->cntpoff_el2);
  write_cntvoff_el2(sysregs->cntvoff_el2);
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

  sysregs->cntpoff_el2 = read_cntpoff_el2();
  sysregs->cntvoff_el2 = read_cntvoff_el2();
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
  if ((enter->flags & RSI_ENTER_GIC_OWNER) == 0) {
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

void exit_aux_plane(struct rec *rec, unsigned long exit_reason)
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
  unsigned long rec_idx;
  struct p0_state *p0_state;

  rec_idx = rec->rec_idx;
  panic_if(rec_idx >= MAX_RECS, "REC index out of range");
  p0_state = &p0_states[rec_idx];

  if (p0_state->current_plane_index != 0
      || rec->gic_owner != p0_state->current_plane_index
      || rec->sysregs.gicstate.ich_misr_el2 != 0) {
    INFO("[Plane]\tREC %lu is in aux plane %lu, GIC owner %lu, GIC MISR 0x%lx\n",
         rec_idx, p0_state->current_plane_index, rec->gic_owner, rec->sysregs.gicstate.ich_misr_el2);
    exit_aux_plane(rec, RSI_EXIT_IRQ);
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
  if ((run->enter.flags & RSI_ENTER_GIC_OWNER) != 0) {
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
