import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {InspectionTools} from '../apps/api/src/inspection-tools.js';
import {configSchema} from '../packages/connectors/src/config.js';
import type {Database} from '../packages/storage/src/db.js';

const require=createRequire(import.meta.url);
const {allowedImageFile,imageVersionField}=require('../collectors/oci/image-file-evidence.mjs');

test('image file evidence returns a chosen version value without raw content',()=>{
  assert(allowedImageFile('/app/vendor/package.json'));
  assert(!allowedImageFile('/app/../etc/os-release'));
  assert(!allowedImageFile('/app/.env'));
  assert(!allowedImageFile('/run/secrets/example'));
  assert.equal(imageVersionField(Buffer.from('{"vendor":{"version":"5.2.0","password":"private"}}'),['vendor','version']),'5.2.0');
  assert.equal(imageVersionField(Buffer.from('JAVA_VERSION="21.0.9"'),['JAVA_VERSION']),'21.0.9');
  assert.equal(imageVersionField(Buffer.from('VERSION_ID=3.23.3'),['VERSION_ID']),'3.23.3');
  assert.equal(imageVersionField(Buffer.from('1.5.7\n'),[]),'1.5.7');
  assert.equal(imageVersionField(Buffer.from('{"vendor":{"password":"5.2.0"}}'),['vendor','password']),null);
  assert.equal(imageVersionField(Buffer.from('version=5.2.0\nversion=6.0.0'),['version']),null);
});

test('analysis can query a model-selected package and file only inside the target image scope',async t=>{
  const target='asset',image='example/app:prod',digest='sha256:'+'a'.repeat(64);
  const db={async query(sql:string){
    if(sql.includes('FROM applications'))return [{id:target,name:'app',namespace:'apps',desired_images:[image]}];
    return [];
  }} as unknown as Database;
  const tools=new InspectionTools(db,configSchema.parse({}),{applicationIds:[target],repositories:[],factAssetIds:[],userId:'tester'});
  await tools.init();
  const previous=process.env.SILICONER_IMAGE_CATALOG;
  process.env.SILICONER_IMAGE_CATALOG='true';
  const requested:string[]=[];
  t.mock.method(globalThis,'fetch',async (input:URL)=>{
    requested.push(input.pathname);
    assert.equal(input.searchParams.get('image'),image);
    if(input.pathname==='/catalog'){
      assert.equal(input.searchParams.get('q'),'vendor-custom-tool');
      return Response.json({image,digest,matchCount:1,matches:[{name:'vendor-custom-tool',version:'3.7.0'}]});
    }
    assert.equal(input.searchParams.get('path'),'/vendor/custom/RELEASE');
    assert.deepEqual(input.searchParams.getAll('field'),['release']);
    return Response.json({path:'/vendor/custom/RELEASE',digest,platform:'linux/amd64',size:64,version:'3.7.0',raw:'excluded'});
  });
  try{
    await assert.rejects(tools.call('image_components',{target_id:target,image:'other/image:latest',query:'vendor-custom-tool'}),/inspection_image_out_of_scope/);
    await assert.rejects(tools.call('image_file_evidence',{target_id:target,image:'other/image:latest',path:'/vendor/custom/RELEASE',fields:['release']}),/inspection_image_out_of_scope/);
    assert.deepEqual(requested,[]);
    const search=await tools.call('image_components',{target_id:target,image,query:'vendor-custom-tool'});
    assert.equal(search.evidence[0].facts.matches[0].version,'3.7.0');
    const file=await tools.call('image_file_evidence',{target_id:target,image,path:'/vendor/custom/RELEASE',fields:['release']});
    assert.equal(file.evidence[0].facts.version,'3.7.0');
    assert.equal(file.evidence[0].facts.raw,undefined);
    assert.deepEqual(requested,['/catalog','/file-evidence']);
  }finally{
    if(previous===undefined)delete process.env.SILICONER_IMAGE_CATALOG;
    else process.env.SILICONER_IMAGE_CATALOG=previous;
  }
});
