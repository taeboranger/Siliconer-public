import {randomUUID} from 'node:crypto';
import {ORG,type Queryable} from '../../../packages/storage/src/db.js';
import {hash} from '../../../packages/core/src/util.js';
import {enqueue} from '../../../packages/storage/src/jobs.js';
import {audit} from './inventory.js';
import {targetEvidenceIds,type InspectionEvidence,type Target} from './inspection-tools.js';
import type {z} from 'zod';
import type {investigationPlanSchema,EvaluatedResult} from './investigations.js';

// A service grant gives access to that service's tickets. A creator's other tickets
// retain their original investigation scope checks.
export function ticketAccessSql(user:string){return `(
 EXISTS(SELECT 1 FROM findings tf JOIN service_owners o ON o.organization_id=tf.organization_id AND o.application_id=tf.application_id
   WHERE tf.id=t.finding_id AND tf.organization_id=t.organization_id AND o.user_id=${user})
 OR EXISTS(SELECT 1 FROM service_owners o WHERE o.organization_id=t.organization_id
   AND o.application_id::text=t.target_id AND o.user_id=${user})
 OR EXISTS(SELECT 1 FROM investigation_tickets it JOIN investigations i ON i.organization_id=it.organization_id AND i.id=it.investigation_id
   WHERE it.ticket_id=t.id AND it.organization_id=t.organization_id AND i.created_by=${user}
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(i.scope->'applicationIds') AS ids(id)
     WHERE NOT EXISTS(SELECT 1 FROM service_owners o WHERE o.organization_id=t.organization_id AND o.user_id=${user} AND o.application_id=ids.id::uuid)))
)`;}

export async function linkInvestigationTickets(tx:Queryable,row:{id:string;title:string;report_text:string;reference_url:string|null},plan:z.infer<typeof investigationPlanSchema>,result:EvaluatedResult,targets:Target[],evidence:InspectionEvidence[]){
  const ids:string[]=[],affectedIds:string[]=[];
  // Stable report text + target identity survives forced runs and changing asset evidence.
  const reportHash=hash(row.report_text.trim());
  for(const target of result.targets){
    const sourceKey=hash({report:reportHash,target:target.target_id});
    const [previous]=await tx.query('SELECT id FROM tickets WHERE organization_id=$1 AND source_key=$2',[ORG,sourceKey]);
    // Only confirmed impact opens a ticket. Existing tickets retain their assessment history;
    // human workflow state is never automatically closed or reopened.
    if(target.status!=='affected'&&!previous)continue;
    const asset=targets.find(t=>t.id===target.target_id)!;
    const cited=new Set(targetEvidenceIds(target));
    const context={report_title:row.title,reference_url:row.reference_url,target_kind:asset.kind,
      threat:plan.threat,response_summary:target.response_summary,version_comparison:target.version_comparison,check_definitions:plan.checks,applicability:target.applicability,applicability_reason:target.applicability_reason,
      explanation:target.explanation,confidence:target.confidence,products:plan.products,checks:target.checks,
      recommended_actions:target.recommended_actions,limitations:result.limitations,
      evidence:evidence.filter(e=>cited.has(e.id))};
    const assessmentHash=hash({status:target.status,context});
    const [ticket]=await tx.query(`INSERT INTO tickets(id,organization_id,source_key,title,target_id,target_name,assessment_status,context,assessment_hash)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT(organization_id,source_key) WHERE source_key IS NOT NULL DO UPDATE
      SET title=EXCLUDED.title,target_name=EXCLUDED.target_name,assessment_status=EXCLUDED.assessment_status,
      context=EXCLUDED.context,assessment_hash=EXCLUDED.assessment_hash,
      updated_at=CASE WHEN tickets.assessment_hash IS DISTINCT FROM EXCLUDED.assessment_hash THEN now() ELSE tickets.updated_at END RETURNING id`,
      [randomUUID(),ORG,sourceKey,row.title,target.target_id,asset.name,target.status,JSON.stringify(context),assessmentHash]);
    await tx.query(`INSERT INTO investigation_tickets(organization_id,investigation_id,target_id,ticket_id,assessment) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(organization_id,investigation_id,target_id) DO NOTHING`,[ORG,row.id,target.target_id,ticket.id,JSON.stringify({status:target.status,...context})]);
    ids.push(ticket.id);
    if(target.status==='affected')affectedIds.push(ticket.id);
    const eventHash=hash({ticket:ticket.id,assessmentHash});
    await enqueue(tx,'notify',{ticketId:ticket.id,investigationId:row.id,title:row.title,application:asset.name,status:target.status,eventHash},`notify:${eventHash}`);
    await audit(tx,'worker','ticket.investigation_linked',ticket.id,{investigationId:row.id,targetId:target.target_id,status:target.status});
  }
  return {ids,affectedIds};
}
