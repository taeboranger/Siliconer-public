import test from 'node:test';
import assert from 'node:assert/strict';
import {compareDpkgVersion,distroBrotliFix,nodeBrotliFix} from '../packages/core/src/brotli-advisory.js';

test('uses vendor revisions for backported Brotli fixes',()=>{
  assert.equal(nodeBrotliFix('22.23.3')?.result,'affected');
  assert.equal(nodeBrotliFix('22.23.4')?.result,'fixed');
  assert.equal(nodeBrotliFix('24.22.2')?.result,'fixed');
  assert.equal(nodeBrotliFix('24.22.1-rc.1'),undefined);
  assert.equal(distroBrotliFix('ubuntu','24.04','1.1.0-2ubuntu0.1')?.result,'fixed');
  assert.equal(distroBrotliFix('ubuntu','24.04','1.1.0-2ubuntu0.0')?.result,'affected');
  assert.equal(distroBrotliFix('debian','12.15','1.0.9-2+deb12u1')?.result,'fixed');
  assert.equal(distroBrotliFix('debian','14','1.0.9-2+deb12u1'),undefined);
  assert(compareDpkgVersion('1.0~rc1-2','1.0-1')<0);
  assert(compareDpkgVersion('1.0-10','1.0-2')>0);
  assert(compareDpkgVersion('1:1.0-1','2.0-1')>0);
});
