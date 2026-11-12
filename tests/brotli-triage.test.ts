import test from 'node:test';
import assert from 'node:assert/strict';
import {observedBrotliComparisons,scopedBrotliVerdict} from '../apps/api/src/brotli-triage.js';
import type {InspectionEvidence} from '../apps/api/src/inspection-tools.js';

function observation(id:string,kind:string,source:string,facts:unknown):InspectionEvidence{
  return {id,kind,source,facts,target_id:'application',observed_at:'2026-11-11T00:00:00Z',expires_at:null,complete:true,content_hash:id};
}

test('Brotli triage uses scoped catalog coverage and never excludes unmatched detections',()=>{
  const digest='sha256:'+'a'.repeat(64);
  const image=`registry@${digest}`;
  const scan=(binaries:unknown[],matches:unknown[]=[])=>observation('scan','image_catalog','syft:registry',{
    requested_image:image,digest,binaries,matches,matchCount:matches.length,artifactCount:100,
  });
  const catalog=(evidence:InspectionEvidence[])=>({evidence,unavailable:[],unscanned:0});
  const clean=catalog([scan([])]);
  assert.equal(scopedBrotliVerdict(clean,[],[])?.status,'not_affected');
  assert.equal(scopedBrotliVerdict({...clean,unscanned:1},[],[]),null);
  assert.equal(scopedBrotliVerdict(catalog([scan([],[{name:'brotli',version:'1.2.0'}])]),[],[]),null);
  const node=catalog([scan([{name:'node'}])]);
  assert.equal(scopedBrotliVerdict(node,[],[]),null);
  const runtime=observation('runtime','deployment_observed','collector:node-runtime-versions',{digest,node_version:'24.22.2',brotli_version:'1.2.0'});
  const fix=observation('fix','vendor_fix','Node.js',{observed_evidence_id:runtime.id,component:'Node.js 내장 Brotli',
    runtime_version:'24.22.2',version:'1.2.0',fix_version:'24.22.1',status:'fixed'});
  assert.equal(scopedBrotliVerdict(node,[fix],[runtime])?.status,'not_affected');
  const duplicate={...fix,id:'fix-replica'};
  assert.deepEqual(observedBrotliComparisons([fix,duplicate]).map(row=>row.evidence_ids),[['fix','runtime','fix-replica']]);
});
