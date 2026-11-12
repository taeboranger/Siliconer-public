import {z} from 'zod';
export const githubReadPermissions={contents:'read',actions:'read',metadata:'read'} as const;
export function githubAppManifest(redirectUrl:string){
  const redirect=new URL(redirectUrl);
  if(redirect.protocol!=='http:'||redirect.hostname!=='127.0.0.1')throw new Error('Setup callback must stay on the operator loopback interface');
  return {name:'Siliconer',url:'https://siliconer.example.invalid',description:'Read-only security report inspection for selected home-server repositories.',public:false,redirect_url:redirectUrl,setup_url:'https://siliconer.example.invalid/?github_app=installed',request_oauth_on_install:false,setup_on_update:false,hook_attributes:{url:'https://siliconer.example.invalid/api/v1/webhooks/github/home-github',active:false},default_permissions:githubReadPermissions,default_events:[]};
}
const repoSchema=z.object({full_name:z.string().regex(/^[\w.-]+\/[\w.-]+$/),default_branch:z.string().min(1).max(200)});
export function validateGithubInstallation(raw:unknown,appId:number,owner:string){
  const install=z.object({id:z.number().int().positive(),app_id:z.number().int().positive(),account:z.object({login:z.string()}),repository_selection:z.literal('selected'),permissions:z.record(z.string(),z.string()),suspended_at:z.string().nullable().optional()}).parse(raw);
  if(install.app_id!==appId||install.account.login.toLowerCase()!==owner.toLowerCase()||install.suspended_at)throw new Error('Installation does not match the authorized account and app');
  if(Object.entries(install.permissions).some(([name,level])=>level!=='read'||!(name in githubReadPermissions))||Object.keys(githubReadPermissions).some(name=>install.permissions[name]!=='read'))throw new Error('Installation must have only the expected read permissions');
  return install;
}
export function githubConnectorDraft(appId:number,installationId:number,repositories:unknown[]){
  const repos=repositories.map(r=>repoSchema.parse(r));
  if(!repos.length||repos.length>100)throw new Error('Select 1–100 repositories');
  return {id:'home-github',name:'Home GitHub App',kind:'github',appId:String(appId),installationId,privateKeyFileEnv:'GITHUB_APP_PRIVATE_KEY_FILE',repositories:repos.map(r=>({name:r.full_name,kind:/config$/i.test(r.full_name)?'gitops':'source',ref:r.default_branch})),sourcePolicies:repos.filter(r=>!/config$/i.test(r.full_name)).map(r=>({repository:r.full_name,allowCodeEgress:true,allowedPaths:['package.json','apps/web/package.json','pnpm-lock.yaml','package-lock.json','pom.xml','build.gradle','build.gradle.kts','requirements.txt','pyproject.toml','go.mod','go.sum','Dockerfile'],allowedPathPrefixes:[],packageManifestPath:'package.json'}))};
}
