import semver from 'semver';

export const brotliCve='CVE-2026-111497';
export const nodeBrotliNotice='https://nodejs.org/en/blog/vulnerability/october-2026-security-releases';
const debianNotice='https://security-tracker.debian.org/tracker/CVE-2026-111497';
const ubuntuNotice='https://ubuntu.com/security/notices/USN-8956-1';
const nodeFixes:Record<number,string>={22:'22.23.4',24:'24.22.1',26:'26.12.1'};
const ubuntuFixes:Record<string,string>={'22.04':'1.0.9-2ubuntu0.1','24.04':'1.1.0-2ubuntu0.1','26.04':'1.2.0-3ubuntu0.1','26.10':'1.2.0-4ubuntu0.1'};
const debianFixes:Record<string,string>={'12':'1.0.9-2+deb12u1','13':'1.1.0-2+deb13u1'};

export function nodeBrotliFix(version:string){
  const node=semver.parse(version);
  if(!node||node.prerelease.length)return;
  const fixedVersion=nodeFixes[node.major];
  if(!fixedVersion)return;
  return {fixedVersion,result:semver.gte(node,fixedVersion)?'fixed' as const:'affected' as const,reference:nodeBrotliNotice};
}

function compareRevision(left:string,right:string){
  const order=(c:string)=>c==='~'?-1:!c||/[0-9]/.test(c)?0:/[A-Za-z]/.test(c)?c.charCodeAt(0):c.charCodeAt(0)+256;
  let a=0,b=0;
  while(a<left.length||b<right.length){
    while((left[a]&&!/[0-9]/.test(left[a]))||(right[b]&&!/[0-9]/.test(right[b]))){
      const result=order(left[a]??'')-order(right[b]??'');
      if(result)return result;
      if(left[a])a++;
      if(right[b])b++;
    }
    const digitsA=(/^[0-9]*/.exec(left.slice(a))?.[0]??'');
    const digitsB=(/^[0-9]*/.exec(right.slice(b))?.[0]??'');
    const x=digitsA.replace(/^0+/,'');
    const y=digitsB.replace(/^0+/,'');
    if(x.length!==y.length)return x.length-y.length;
    if(x!==y)return x<y?-1:1;
    a+=digitsA.length;b+=digitsB.length;
  }
  return 0;
}

export function compareDpkgVersion(left:string,right:string){
  const parse=(value:string)=>{
    const colon=value.indexOf(':'),body=value.slice(colon+1),dash=body.lastIndexOf('-');
    return {epoch:colon<0?0n:BigInt(value.slice(0,colon)),upstream:dash<0?body:body.slice(0,dash),revision:dash<0?'0':body.slice(dash+1)};
  };
  const a=parse(left),b=parse(right);
  if(a.epoch!==b.epoch)return a.epoch<b.epoch?-1:1;
  return compareRevision(a.upstream,b.upstream)||compareRevision(a.revision,b.revision);
}

export function distroBrotliFix(distribution:string,release:string,version:string){
  if(!/^(?:\d+:)?\d[\w.+~:-]{0,119}$/.test(version))return;
  const fixedVersion=distribution==='ubuntu'?ubuntuFixes[release]:distribution==='debian'?debianFixes[release.split('.')[0]]:undefined;
  if(!fixedVersion)return;
  return {fixedVersion,result:compareDpkgVersion(version,fixedVersion)>=0?'fixed' as const:'affected' as const,
    reference:distribution==='ubuntu'?ubuntuNotice:debianNotice};
}
