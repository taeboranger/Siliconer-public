import { z } from 'zod';
import { openDatabase, migrate } from '../../../packages/storage/src/db.js';
import { readSettings } from './config.js';
import { createUser } from './auth.js';
import {loadConnectorConfig} from '../../../packages/connectors/src/config.js';
import {ORG} from '../../../packages/storage/src/db.js';
import {InspectionTools,allowedScope} from './inspection-tools.js';
import {audit} from './inventory.js';
const settings = readSettings(); const db = await openDatabase(settings.databaseUrl, settings.production);
try {
  if (process.argv[2] === 'migrate') { await migrate(db); console.log('Database migrations applied.'); }
  else if (process.argv[2] === 'admin') {
    const email = z.email().parse(process.env.SILICONER_ADMIN_EMAIL);
    const password = z.string().min(14).max(256).parse(process.env.SILICONER_ADMIN_PASSWORD);
    await createUser(db, email, password); console.log('Administrator created.');
  } else if(process.argv[2]==='record-node-versions'){
    const version=z.string().regex(/^\d+\.\d+\.\d+$/);
    const [app,digest,container,node,brotli]=z.tuple([z.uuid(),z.string().regex(/^sha256:[a-f0-9]{64}$/),
      z.string().regex(/^[a-z0-9-]{1,63}$/),version,version]).parse(process.argv.slice(3));
    await db.transaction(async tx=>{
      const [snapshot]=await tx.query(`SELECT containers,expires_at>now() AS fresh FROM snapshots WHERE organization_id=$1 AND application_id=$2
        ORDER BY observed_at DESC,id DESC LIMIT 1`,[ORG,app]);
      if(!snapshot?.fresh||!snapshot.containers.some((c:any)=>c.running&&c.kind==='regular'&&c.container===container&&c.digest===digest))
        throw Error('A fresh running snapshot must match the image digest and container');
      const rows=await tx.query(`INSERT INTO image_runtime_versions(organization_id,application_id,digest,container_name,node_version,brotli_version)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING digest`,[ORG,app,digest,container,node,brotli]);
      if(!rows.length){
        const [prior]=await tx.query('SELECT node_version,brotli_version FROM image_runtime_versions WHERE organization_id=$1 AND application_id=$2 AND digest=$3 AND container_name=$4',[ORG,app,digest,container]);
        if(prior?.node_version!==node||prior?.brotli_version!==brotli)throw Error('Conflicting version observation for the same image');
      }else await audit(tx,'operator','runtime.node_versions_recorded',app,{digest,container,node,brotli});
    });
    console.log('Node runtime versions recorded.');
  } else if(process.argv[2]==='dependency-versions'){
    const config=await loadConnectorConfig(settings.configFile),[user]=await db.query("SELECT id FROM users WHERE organization_id=$1 AND role='admin' ORDER BY created_at LIMIT 1",[ORG]);
    if(!user)throw Error('Administrator missing');
    const tools=new InspectionTools(db,config,await allowedScope(db,config,user.id));await tools.init();
    for(const target of tools.targets.filter(t=>t.kind==='application'&&(!process.argv[3]||t.name===process.argv[3]))){
      const result=await tools.call('dependency_versions',{target_id:target.id,query:process.argv[4]??'next'});
      console.log(JSON.stringify({name:target.name,sources:target.metadata.source_repositories,evidence:result.evidence.map((e:any)=>({id:e.id,...e.facts})),unavailable:result.unavailable,missing:result.missing}));
    }
  } else throw new Error('Usage: cli migrate | admin | dependency-versions [application] [query] | record-node-versions <app-id> <digest> <container> <node> <brotli>');
} finally { await db.close(); }
