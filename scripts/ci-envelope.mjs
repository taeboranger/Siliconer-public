import fs from 'node:fs/promises';
import { createHash, sign } from 'node:crypto';
function canonical(value) {
  if(Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if(value && typeof value==='object') return `{${Object.entries(value).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}
const [sbomFile,outputFile] = process.argv.slice(2);
if(!sbomFile || !outputFile) throw new Error('Usage: ci-envelope <sbom.json> <envelope.json>');
const { GITHUB_REPOSITORY:repository,GITHUB_SHA:commitSha,GITHUB_RUN_ID:workflowRunId,SILICONER_IMAGE:image,SILICONER_IMAGE_DIGEST:digest,SILICONER_CI_SIGNING_KEY_FILE:keyFile }=process.env;
if(!/^[\w.-]+\/[\w.-]+$/.test(repository ?? '') || !/^[a-f0-9]{40}$/.test(commitSha ?? '') || !/^\d+$/.test(workflowRunId ?? '') || !/^sha256:[a-f0-9]{64}$/.test(digest ?? '') || !image || !keyFile) throw new Error('Required CI identity, image digest or signing-key reference is missing');
const sbom=JSON.parse(await fs.readFile(sbomFile,'utf8'));
const sbomHash=createHash('sha256').update(canonical(sbom)).digest('hex');
const runAttempt=Number(process.env.GITHUB_RUN_ATTEMPT ?? '1');
const envelope={repository,commitSha,image,digest,workflowRunId,runAttempt,sbomHash,complete:process.env.SILICONER_SBOM_COMPLETE==='true'};
const signature=sign(null,Buffer.from(canonical(envelope)),await fs.readFile(keyFile,'utf8')).toString('base64');
await fs.writeFile(outputFile,JSON.stringify({...envelope,sbom,signature}),{mode:0o600});
console.log('Signed SBOM envelope written. Upload only after the referenced build workflow succeeds.');
