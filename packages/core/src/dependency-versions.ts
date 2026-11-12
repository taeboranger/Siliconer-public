import {parseDocument} from 'yaml';
export const dependencyBasenames=new Set(['package.json','package-lock.json','pnpm-lock.yaml','yarn.lock','pom.xml','build.gradle','build.gradle.kts','requirements.txt','pyproject.toml','poetry.lock','uv.lock','go.mod','go.sum','Cargo.toml','Cargo.lock','composer.json','composer.lock','Gemfile','Gemfile.lock','Dockerfile']);
export interface DependencyVersion{name:string;version:string;basis:'declared'|'resolved'|'checksum_record';path:string}
export function dependencyVersions(path:string,text:string):DependencyVersion[]{
  const name=path.split('/').at(-1),out:DependencyVersion[]=[];
  const object=(v:any)=>v!==null&&typeof v==='object'&&!Array.isArray(v);
  const add=(n:unknown,v:unknown,basis:DependencyVersion['basis'])=>{if(typeof n==='string'&&typeof v==='string'&&n.length<=200&&v.length<=300)out.push({name:n,version:v,basis,path});};
  if(name==='package.json'){const j=JSON.parse(text);if(!object(j))throw Error('Invalid package manifest');add(j.name,j.version,'declared');for(const group of ['dependencies','devDependencies','optionalDependencies','peerDependencies']){if(j[group]!==undefined&&!object(j[group]))throw Error('Invalid dependency declarations');for(const [n,v] of Object.entries(j[group]??{})){if(typeof v!=='string')throw Error('Invalid dependency version');add(n,v,'declared');}}}
  if(name==='package-lock.json'){
    const j=JSON.parse(text);
    if(!object(j)||(j.packages!==undefined&&!object(j.packages))||(j.dependencies!==undefined&&!object(j.dependencies))||(!j.packages&&!j.dependencies&&typeof j.lockfileVersion!=='number'))throw Error('Invalid npm lockfile');
    if(j.packages)for(const [p,v] of Object.entries(j.packages) as [string,any][]){if(p.includes('node_modules/'))add(v.name??p.split('node_modules/').at(-1),v.version,'resolved');}
    const walk=(list:any,depth=0)=>{if(depth>30)throw Error('Dependency graph depth limit');for(const [n,v] of Object.entries(list??{}) as [string,any][]){add(n,v.version,'resolved');walk(v.dependencies,depth+1);}};walk(j.dependencies);
  }
  if(name==='pnpm-lock.yaml'||name==='yarn.lock'){
    const doc=parseDocument(text,{uniqueKeys:true});if(doc.errors.length)throw Error('Invalid dependency lockfile');const j=doc.toJS({maxAliasCount:0});if(!object(j)||(name==='pnpm-lock.yaml'&&j.packages!==undefined&&!object(j.packages)))throw Error('Invalid dependency lockfile');
    if(name==='pnpm-lock.yaml')for(const key of Object.keys(j.packages??{})){
      const k=key.replace(/^\//,''),m=/^((?:@[^/]+\/)?[^@/]+)(?:@|\/)([^(/]+)(?:\(|$)/.exec(k);if(m)add(m[1],m[2],'resolved');
    }
    else for(const [key,v] of Object.entries(j??{}) as [string,any][]){const m=/^((?:@[^/]+\/)?[^@]+)@/.exec(key);if(m)add(m[1],v?.version,'resolved');}
  }
  if(name==='composer.lock'){const j=JSON.parse(text);for(const p of [...(j.packages??[]),...(j['packages-dev']??[])])add(p.name,p.version,'resolved');}
  if(name==='go.mod'||name==='go.sum')for(const line of text.split('\n')){const m=/^\s*(?:require\s+)?([\w.-]+\/[\w./-]+)\s+(v\S+)/.exec(line);if(m)add(m[1],m[2].replace(/\/go\.mod$/,''),name==='go.sum'?'checksum_record':'declared');}
  if(out.length>20000)throw Error('Dependency inventory size limit');
  return [...new Map(out.map(v=>[JSON.stringify(v),v])).values()];
}
