import {createHash} from 'node:crypto';
import {writeFile,unlink} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';

const version='1.57.1';
const expected='bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c';
const archive='/tools/syft.tar.gz';
const response=await fetch(`https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_linux_amd64.tar.gz`,
  {signal:AbortSignal.timeout(90000)});
if(!response.ok)throw Error('scanner_download_failed');
const chunks=[];
let size=0;
for await(const chunk of response.body){
  size+=chunk.length;
  if(size>50*1024*1024)throw Error('scanner_download_too_large');
  chunks.push(chunk);
}
const bytes=Buffer.concat(chunks);
if(createHash('sha256').update(bytes).digest('hex')!==expected)throw Error('scanner_checksum_mismatch');
await writeFile(archive,bytes,{mode:0o600});
try{execFileSync('tar',['-xzf',archive,'-C','/tools','syft'],{timeout:15000});}
finally{await unlink(archive);}

const regctl=await fetch('https://github.com/regclient/regclient/releases/download/v0.11.7/regctl-linux-amd64',
  {signal:AbortSignal.timeout(60000)});
if(!regctl.ok)throw Error('regctl_download_failed');
const regctlParts=[];
let regctlSize=0;
for await(const chunk of regctl.body){
  regctlSize+=chunk.length;
  if(regctlSize>40*1024*1024)throw Error('regctl_download_too_large');
  regctlParts.push(chunk);
}
const binary=Buffer.concat(regctlParts);
if(createHash('sha256').update(binary).digest('hex')!=='3737fbbdd791e04e7a831640b681f3397a376498e80e2ad9b1b2d27296f239bc')
  throw Error('regctl_checksum_mismatch');
await writeFile('/tools/regctl',binary,{mode:0o500});
