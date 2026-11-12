// Read constant-return version symbols in little-endian x86-64 ELF files.
// The inspected image binary is never loaded or executed.
export function readElfBrotli(data){
  if(data.length<64||data.readUInt32BE(0)!==0x7f454c46||data[4]!==2||data[5]!==1||data.readUInt16LE(18)!==62)return;
  const u64=offset=>Number(data.readBigUInt64LE(offset));
  const sectionOffset=u64(40),sectionSize=data.readUInt16LE(58),count=data.readUInt16LE(60);
  if(sectionSize<64||!Number.isSafeInteger(sectionOffset)||sectionOffset+sectionSize*count>data.length||count>4096)return;
  const sections=Array.from({length:count},(_,index)=>{
    const offset=sectionOffset+index*sectionSize;
    return {type:data.readUInt32LE(offset+4),address:u64(offset+16),offset:u64(offset+24),size:u64(offset+32),
      link:data.readUInt32LE(offset+40),entrySize:u64(offset+56)};
  });
  const bounded=section=>section&&Number.isSafeInteger(section.offset)&&Number.isSafeInteger(section.size)&&section.offset+section.size<=data.length;
  const names=['BrotliDecoderVersion','BrotliEncoderVersion'];
  const versions=new Map();
  for(const table of sections.filter(s=>(s.type===2||s.type===11)&&bounded(s)&&s.entrySize>=24&&s.entrySize<=64)){
    const strings=sections[table.link];
    if(!bounded(strings))continue;
    for(let offset=table.offset;offset+24<=table.offset+table.size;offset+=table.entrySize){
      const start=data.readUInt32LE(offset);
      if(start>=strings.size)continue;
      const index=sections[data.readUInt16LE(offset+6)];
      if(!bounded(index)||(data[offset+4]&15)!==2)continue;
      const label=names.find(n=>start+n.length<strings.size&&data[strings.offset+start+n.length]===0&&
        data.toString('ascii',strings.offset+start,strings.offset+start+n.length)===n);
      if(!label)continue;
      const address=u64(offset+8),size=u64(offset+16);
      let code=index.offset+address-index.address;
      if(!Number.isSafeInteger(code)||code<index.offset||size<6||size>32||code+size>index.offset+index.size)continue;
      if(data.readUInt32BE(code)===0xf30f1efa){code+=4;if(size<10)continue;}
      if(data[code]!==0xb8||data[code+5]!==0xc3)continue;
      const packed=data.readUInt32LE(code+1);
      const major=packed>>>24,minor=(packed>>>12)&0xfff,patch=packed&0xfff;
      if(major>0&&major<=10&&minor<100&&patch<100)versions.set(label,`${major}.${minor}.${patch}`);
    }
  }
  const decoder=versions.get(names[0]);
  return decoder&&decoder===versions.get(names[1])?decoder:undefined;
}
