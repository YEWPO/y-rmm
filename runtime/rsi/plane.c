#include <rec.h>
#include <rsi-handler.h>
#include <smc-rsi.h>

void handle_rsi_plane_enter(struct rec *rec, struct rsi_result *res)
{
  (void)rec;

  res->action = UPDATE_REC_RETURN_TO_REALM;
  res->smc_res.x[0] = RSI_SUCCESS;
}
