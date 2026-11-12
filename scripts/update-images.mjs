import fs from 'node:fs/promises';
import path from 'node:path';
import { parseDocument } from 'yaml';
const [directory,api,web] = process.argv.slice(2);
if (!directory || ![api,web].every(s=>/^[\w./:-]+@sha256:[a-f0-9]{64}$/.test(s ?? ''))) throw new Error('Usage: update-images <overlay-directory> <api-repo@digest> <web-repo@digest>');
const file=path.resolve(directory,'kustomization.yaml');
const doc=parseDocument(await fs.readFile(file,'utf8'));
if(doc.errors.length) throw new Error('Invalid kustomization');
const images=doc.get('images')?.toJSON();
if(!Array.isArray(images)) throw new Error('Expected existing images entries');
for(const [name,ref] of [['example-owner/siliconer-api-prod',api],['example-owner/siliconer-web-prod',web]]) {
  const item=images.find(i=>i.name===name); if(!item) throw new Error(`Missing image entry ${name}`);
  const [newName,digest]=ref.split('@'); item.newName=newName;item.digest=digest;delete item.newTag;
}
doc.set('images',images);await fs.writeFile(file,doc.toString());
