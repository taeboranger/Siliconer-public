import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const [image,output,expected]=process.argv.slice(2);
if(!/^[\w./:-]+@sha256:[a-f0-9]{64}$/.test(image??'')||!output)throw Error('Usage: brotli-sbom <image@digest> <output.json> [expected-version]');
const version=execFileSync('docker',['run','--rm','--network=none','--read-only','--cap-drop=ALL',
  '--security-opt=no-new-privileges','--entrypoint=node',image,'-p','process.versions.brotli'],{encoding:'utf8',timeout:90000}).trim();
if(!/^\d+\.\d+\.\d+$/.test(version)||(expected&&version!==expected))throw Error('Brotli version check failed');
writeFileSync(output,JSON.stringify({bomFormat:'CycloneDX',specVersion:'1.5',version:1,components:[
  {type:'library',name:'node-bundled-brotli',version,purl:`pkg:generic/node-bundled-brotli@${version}`},
]}));
