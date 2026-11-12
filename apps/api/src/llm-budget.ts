import {z} from 'zod';
import {ORG,type Queryable} from '../../../packages/storage/src/db.js';
import {AppError} from '../../../packages/core/src/types.js';

export const budgetSettings=z.strictObject({
  dailyCalls:z.number().int().min(1).max(1000),
  subscriptionPercent:z.number().int().min(1).max(100),
});

export async function readLlmBudget(db:Queryable,defaultCalls:number){
  const [row]=await db.query<{daily_calls:number;subscription_percent:number}>(
    'SELECT daily_calls,subscription_percent FROM llm_budget_settings WHERE organization_id=$1',[ORG]);
  return {dailyCalls:row?.daily_calls??defaultCalls,subscriptionPercent:row?.subscription_percent??100};
}

export async function reserveCodexCall(tx:Queryable,defaultCalls:number){
  // Serialize reservations and settings changes across API and Worker processes.
  await tx.query('SELECT id FROM organizations WHERE id=$1 FOR NO KEY UPDATE',[ORG]);
  const budget=await readLlmBudget(tx,defaultCalls);
  if(budget.subscriptionPercent<100){
    const [account]=await tx.query<{limits:{usedPercent:number;resetsAt:number}[]}>(
      "SELECT limits FROM model_accounts WHERE organization_id=$1 AND provider='codex'",[ORG]);
    if(account?.limits.some(window=>window.resetsAt*1000>Date.now()&&window.usedPercent>=budget.subscriptionPercent))
      throw new AppError('llm_subscription_budget_reached',409);
  }
  await tx.query("INSERT INTO llm_call_budgets(organization_id,day,provider) VALUES($1,current_date,'codex') ON CONFLICT DO NOTHING",[ORG]);
  const rows=await tx.query("UPDATE llm_call_budgets SET calls=calls+1 WHERE organization_id=$1 AND day=current_date AND provider='codex' AND calls<$2 RETURNING calls",[ORG,budget.dailyCalls]);
  if(!rows.length)throw new AppError('llm_call_limit',409);
}
