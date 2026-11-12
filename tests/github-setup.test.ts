import test from 'node:test';
import assert from 'node:assert/strict';
import {githubAppManifest,githubConnectorDraft,validateGithubInstallation} from '../packages/connectors/src/github-setup.js';
import {configSchema} from '../packages/connectors/src/config.js';
import {githubRepository} from '../packages/connectors/src/github.js';
test('GitHub App setup is private, read-only and validates selected installation ownership',()=>{
  const manifest=githubAppManifest('http://127.0.0.1:8789/callback');assert.equal(manifest.public,false);assert.equal(manifest.hook_attributes.active,false);assert.deepEqual(manifest.default_permissions,{contents:'read',actions:'read',metadata:'read'});assert.throws(()=>githubAppManifest('https://example.invalid/callback'));
  const install={id:7,app_id:11,account:{login:'example-owner'},repository_selection:'selected',permissions:manifest.default_permissions,suspended_at:null};assert.equal(validateGithubInstallation(install,11,'example-owner').id,7);
  assert.throws(()=>validateGithubInstallation({...install,app_id:99},11,'example-owner'));assert.throws(()=>validateGithubInstallation({...install,repository_selection:'all'},11,'example-owner'));assert.throws(()=>validateGithubInstallation({...install,account:{login:'other'}},11,'example-owner'));assert.throws(()=>validateGithubInstallation({...install,permissions:{...manifest.default_permissions,contents:'write'}},11,'example-owner'));
  const draft=githubConnectorDraft(11,7,[{full_name:'example-owner/Siliconer',default_branch:'main'},{full_name:'example-owner/Siliconer-config',default_branch:'main'}]);configSchema.parse({integrations:[draft]});assert.deepEqual(draft.sourcePolicies[0].allowedPathPrefixes,[]);assert(!draft.sourcePolicies[0].allowedPaths.includes('.env'));assert.equal(draft.repositories[1].kind,'gitops');
  for(const url of ['https://github.com/example-owner/Siliconer-config.git','git@github.com:example-owner/Siliconer-config.git','ssh://git@github.com/example-owner/Siliconer-config.git'])assert.equal(githubRepository(url),'example-owner/Siliconer-config');
  assert.equal(githubRepository('https://github.com.attacker.invalid/test/repo'),undefined);
});
