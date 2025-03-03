#include <debug.h>
#include <buffer.h>
#include <realm.h>
#include <granule.h>
#include <rec.h>
#include <rsi-handler.h>
#include <smc-rsi.h>

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

  INFO("Aux-plane's index = %d, pc = 0x%lx\n", plane_index, run->enter.pc);

  /* Unmap rd granule and PlaneRun granule */
  buffer_unmap(rd);
  buffer_unmap(run);

  /* Unlock last level RTT */
  granule_unlock(walk_res.llt);

  /* Write result values */
  res->smc_res.x[0] = RSI_SUCCESS;
}
