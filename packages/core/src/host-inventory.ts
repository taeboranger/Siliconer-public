import {z} from 'zod';

// Package data only: no maintainer scripts, descriptions, paths or environment.
export const hostInventorySchema=z.object({
  format:z.literal('dpkg'),scope:z.literal('host_installed_packages'),complete:z.boolean(),
  packages:z.array(z.object({
    name:z.string().regex(/^[a-z0-9][a-z0-9+.-]{0,199}$/),version:z.string().regex(/^[a-zA-Z0-9.+:~_-]{1,200}$/),
    architecture:z.string().regex(/^[a-z0-9-]{1,40}$/),
    source_name:z.string().regex(/^[a-z0-9][a-z0-9+.-]{0,199}$/),source_version:z.string().regex(/^[a-zA-Z0-9.+:~_-]{1,200}$/),
  }).strict()).max(10000),
}).strict().superRefine((v,ctx)=>{
  const ids=v.packages.map(p=>p.name+':'+p.architecture);
  if(new Set(ids).size!==ids.length)ctx.addIssue({code:'custom',message:'Duplicate installed package'});
});
export type HostInventory=z.infer<typeof hostInventorySchema>;
export function hostSummary(facts:any){
  const {host_inventory,...summary}=facts;
  return {...summary,...(host_inventory?{package_inventory:{format:host_inventory.format,scope:host_inventory.scope,complete:host_inventory.complete,count:host_inventory.packages.length}}:{})};
}
export function selectHostPackages(inventory:HostInventory,query:string){
  const terms=query.toLowerCase().split('|').map(s=>s.trim()).filter(Boolean);
  const matched=inventory.packages.filter(p=>!terms.length||terms.some(t=>p.name.includes(t)||p.source_name.includes(t)));
  return {format:inventory.format,scope:inventory.scope,inventory_complete:inventory.complete,total:inventory.packages.length,
    query,matched:matched.length,partial:matched.length>50,packages:matched.slice(0,50),
    absence_scope:'Only dpkg installed packages; excludes containers, manually installed binaries, language packages and stopped/running service state.'};
}
