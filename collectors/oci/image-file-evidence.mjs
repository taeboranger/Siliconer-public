const version=/^v?\d{1,8}\.\d{1,8}(?:[0-9A-Za-z.+_~-]{0,42})$/;
const sensitive=/(?:^|[._-])(?:env|secret|secrets|credential|credentials|token|password|shadow|passwd|key|keys)(?:[._-]|$)/i;

export function allowedImageFile(path){
  if(typeof path!=='string'||path.length>300||!/^\/[A-Za-z0-9._+@/-]+$/.test(path))return false;
  const segments=path.slice(1).split('/');
  if(/^(?:dev|proc|sys|run|root|home)$/.test(segments[0]))return false;
  return segments.every(segment=>segment&&segment!=='.'&&segment!=='..'&&!sensitive.test(segment)&&
    !/^(?:\.ssh|\.docker|\.npmrc|\.pypirc|id_rsa)$|\.(?:pem|p12|pfx|jks|keystore)$/i.test(segment));
}

export function imageVersionField(bytes,fields){
  if(!Array.isArray(fields)||fields.length>6||fields.some(field=>typeof field!=='string'||
    !/^[a-zA-Z0-9_.-]{1,70}$/.test(field)||sensitive.test(field)))return null;
  const text=bytes.toString('utf8');
  if(text.includes('\0')||text.includes('\ufffd'))return null;
  let value;
  if(!fields.length){
    value=text.trim();
  }else{
    const leaf=fields.at(-1);
    if(!/(?:version(?:[-_.]?(?:id|name))?|release|revision)$/i.test(leaf))return null;
    try{
      value=JSON.parse(text);
      for(const field of fields){
        if(!value||typeof value!=='object'||!Object.hasOwn(value,field))return null;
        value=value[field];
      }
    }catch{
      if(fields.length!==1)return null;
      const matches=text.split(/\r?\n/).flatMap(line=>{
        const pair=/^\s*([\w.-]+)\s*[:=]\s*(.*?)\s*$/.exec(line);
        return pair?.[1]===leaf?[pair[2].replace(/^(['"])(.*)\1$/,'$2')]:[];
      });
      if(matches.length!==1)return null;
      [value]=matches;
    }
  }
  return typeof value==='string'&&version.test(value)?value:null;
}
