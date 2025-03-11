#include <debug.h>
#include <buffer.h>
#include <realm.h>
#include <plane.h>
#include <granule.h>
#include <rec.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <stdbool.h>

static bool aux_plane_state = false;

bool is_aux_plane(void)
{
  return aux_plane_state;
}

static void load_aux_sysregs(struct rec *rec, STRUCT_TYPE sysreg_state *sysregs)
{
  rec->sysregs.sp_el0 = sysregs->sp_el0;
  rec->sysregs.sp_el1 = sysregs->sp_el1;
  rec->sysregs.elr_el1 = sysregs->elr_el1;
  rec->sysregs.spsr_el1 = sysregs->spsr_el1;
  rec->sysregs.pmcr_el0 = sysregs->pmcr_el0;
  rec->sysregs.tpidrro_el0 = sysregs->tpidrro_el0;
  rec->sysregs.tpidr_el0 = sysregs->tpidr_el0;
  rec->sysregs.csselr_el1 = sysregs->csselr_el1;
  rec->sysregs.sctlr_el1 = sysregs->sctlr_el1;
  rec->sysregs.sctlr2_el1 = sysregs->sctlr2_el1;
  rec->sysregs.actlr_el1 = sysregs->actlr_el1;
  rec->sysregs.cpacr_el1 = sysregs->cpacr_el1;
  rec->sysregs.ttbr0_el1 = sysregs->ttbr0_el1;
  rec->sysregs.ttbr1_el1 = sysregs->ttbr1_el1;
  rec->sysregs.tcr_el1 = sysregs->tcr_el1;
  rec->sysregs.esr_el1 = sysregs->esr_el1;
  rec->sysregs.afsr0_el1 = sysregs->afsr0_el1;
  rec->sysregs.afsr1_el1 = sysregs->afsr1_el1;
  rec->sysregs.far_el1 = sysregs->far_el1;
  rec->sysregs.mair_el1 = sysregs->mair_el1;
  rec->sysregs.vbar_el1 = sysregs->vbar_el1;

  rec->sysregs.contextidr_el1 = sysregs->contextidr_el1;
  rec->sysregs.tpidr_el1 = sysregs->tpidr_el1;
  rec->sysregs.amair_el1 = sysregs->amair_el1;
  rec->sysregs.cntkctl_el1 = sysregs->cntkctl_el1;
  rec->sysregs.par_el1 = sysregs->par_el1;
  rec->sysregs.mdscr_el1 = sysregs->mdscr_el1;
  rec->sysregs.mdccint_el1 = sysregs->mdccint_el1;
  rec->sysregs.disr_el1 = sysregs->disr_el1;
  MPAM(rec->sysregs.mpam0_el1 = sysregs->mpam0_el1;)

  rec->sysregs.cntpoff_el2 = sysregs->cntpoff_el2;
  rec->sysregs.cntvoff_el2 = sysregs->cntvoff_el2;
  rec->sysregs.cntp_ctl_el0 = sysregs->cntp_ctl_el0;
  rec->sysregs.cntp_cval_el0 = sysregs->cntp_cval_el0;
  rec->sysregs.cntv_ctl_el0 = sysregs->cntv_ctl_el0;
  rec->sysregs.cntv_cval_el0 = sysregs->cntv_cval_el0;
}

static void load_aux_state(struct rec *rec, struct rsi_plane_enter *enter, STRUCT_TYPE sysreg_state *sysregs)
{
  INFO("Loading aux state\n");

  load_aux_sysregs(rec, sysregs);

  rec->pc = enter->pc;

  for (int i = 0; i < PLANE_EXIT_NR_GPRS; i++) {
    rec->regs[i] = enter->gprs[i];
  }
}

void handle_rsi_plane_enter(struct rec *rec, struct rsi_result *res)
{
  unsigned int plane_index = rec->regs[1];
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
  load_aux_state(rec, &run->enter, &rd->sysregs[PLANE_TO_ARRAY(plane_index)]);
  aux_plane_state = true;

  /* Unmap rd granule and PlaneRun granule */
  buffer_unmap(rd);
  buffer_unmap(run);

  /* Unlock last level RTT */
  granule_unlock(walk_res.llt);

  /* Write result values */
  res->smc_res.x[0] = RSI_SUCCESS;
}
