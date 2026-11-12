import type {ConnectorConfig} from '../../../packages/connectors/src/config.js';
export function sourceBindings(app:Record<string,any>,config:ConnectorConfig){
  return config.integrations.flatMap(i=>i.kind!=='github'?[]:i.sourcePolicies.filter(p=>p.allowCodeEgress&&i.repositories.some(r=>r.name===p.repository)&&p.applicationBindings.some(b=>b.integrationId===app.integration_id&&b.applicationName===app.name)).map(p=>{
    const binding=p.applicationBindings.find(b=>b.integrationId===app.integration_id&&b.applicationName===app.name)!;
    const commits=(app.desired_images??[]).flatMap((image:string)=>{const m=/^(.*):([a-f0-9]{40})$/.exec(image);return m&&binding.imageRepository===m[1]?[m[2]]:[];});
    const commit=commits.length===1?commits[0]:null;
    return {target_id:`repo:${i.id}:${p.repository}`,repository:p.repository,commit_sha:commit,ref:i.repositories.find(r=>r.name===p.repository)!.ref,basis:commit?'declared_image_commit_tag':'configured_repository_branch',runtime_verified:false};
  }));
}
