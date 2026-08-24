// Read-only FAT12/16/32 browser over a random-access byte source.
// The source must expose async read(offset, length) returning Uint8Array.

const MAX_CHAIN_CLUSTERS = 1_000_000;
const MAX_DIR_BYTES = 16 * 1024 * 1024;
const MAX_EXPORT_BYTES = 128 * 1024 * 1024;

function u16(b,o){return b[o]|(b[o+1]<<8);}
function u32(b,o){return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0;}
function trimAscii(bytes){return String.fromCharCode(...bytes).replace(/[\u0000\u0020]+$/g,'');}
function decodeDosName(entry){
  const base=trimAscii(entry.subarray(0,8)),ext=trimAscii(entry.subarray(8,11));
  return ext?`${base}.${ext}`:base;
}
function lfnPiece(e){
  const positions=[[1,11],[14,26],[28,32]],codes=[];
  for(const [a,b] of positions)for(let i=a;i<b;i+=2){const c=e[i]|(e[i+1]<<8);if(c===0x0000||c===0xffff)continue;codes.push(c);}
  return String.fromCharCode(...codes);
}
function dosDateTime(date,time){
  if(!date)return null; const day=date&31,month=(date>>5)&15,year=1980+((date>>9)&127),sec=(time&31)*2,min=(time>>5)&63,hour=(time>>11)&31;
  if(!day||!month)return null; const d=new Date(year,month-1,day,hour,min,sec); return Number.isNaN(d.getTime())?null:d.toISOString();
}
function safeName(name){return String(name||'').replace(/[\u0000-\u001f]/g,'').trim()||'Sem nome';}
function lfnChecksum(shortName){let sum=0;for(let i=0;i<11;i++)sum=(((sum&1)?0x80:0)+(sum>>>1)+shortName[i])&255;return sum;}

export async function openFat(volume){
  const boot=await volume.read(0,512); const bps=u16(boot,11),spc=boot[13],reserved=u16(boot,14),fatCount=boot[16],rootEntries=u16(boot,17),total16=u16(boot,19),fat16=u16(boot,22),total32=u32(boot,32),fat32=u32(boot,36),rootCluster=u32(boot,44);
  if(![512,1024,2048,4096].includes(bps)||!spc||(spc&(spc-1))!==0||spc>128||!reserved||fatCount<1||fatCount>4)throw new Error('O volume abriu, mas o sistema de arquivos não parece FAT válido.');
  const totalSectors=total16||total32,fatSectors=fat16||fat32,rootDirSectors=Math.ceil(rootEntries*32/bps),firstDataSector=reserved+fatCount*fatSectors+rootDirSectors;
  if(!totalSectors||!fatSectors||firstDataSector>=totalSectors)throw new Error('Estrutura FAT inválida.');
  if(totalSectors*bps>volume.size)throw new Error('O sistema FAT declara tamanho maior que o volume criptografado.');
  const dataSectors=totalSectors-firstDataSector,clusterCount=Math.floor(dataSectors/spc); let type;if(clusterCount<4085)type='FAT12';else if(clusterCount<65525)type='FAT16';else type='FAT32';
  const fatBytes=fatSectors*bps,neededFatBytes=type==='FAT12'?Math.ceil((clusterCount+2)*1.5):type==='FAT16'?(clusterCount+2)*2:(clusterCount+2)*4;
  if(fatBytes<neededFatBytes)throw new Error('Tabela FAT menor que o número de clusters declarado.');
  if(type==='FAT32'&&rootCluster<2)throw new Error('FAT32 sem cluster raiz válido.');
  const fs=new FatFileSystem(volume,{type,bps,spc,reserved,fatCount,rootEntries,totalSectors,fatSectors,rootDirSectors,firstDataSector,clusterCount,rootCluster:type==='FAT32'?rootCluster:0}); await fs.validate(); return fs;
}

export class FatFileSystem{
  constructor(volume,info){this.volume=volume;this.info=info;this.clusterSize=info.bps*info.spc;this.fatOffset=info.reserved*info.bps;this.rootDirOffset=(info.reserved+info.fatCount*info.fatSectors)*info.bps;this.dataOffset=info.firstDataSector*info.bps;this._fatCache=new Map();}
  async validate(){const bytes=await this.volume.read(0,this.info.bps);const sig=bytes[this.info.bps-2]|(bytes[this.info.bps-1]<<8);if(sig!==0xaa55)throw new Error('Assinatura FAT 0x55AA ausente.');}
  isEoc(v){return this.info.type==='FAT12'?v>=0x0ff8:this.info.type==='FAT16'?v>=0xfff8:v>=0x0ffffff8;}
  isBad(v){return this.info.type==='FAT12'?v===0x0ff7:this.info.type==='FAT16'?v===0xfff7:v===0x0ffffff7;}
  async fatByte(offset){const sec=Math.floor(offset/this.info.bps),within=offset%this.info.bps;let b=this._fatCache.get(sec);if(!b){b=await this.volume.read(this.fatOffset+sec*this.info.bps,this.info.bps);this._fatCache.set(sec,b);if(this._fatCache.size>32){const k=this._fatCache.keys().next().value;const old=this._fatCache.get(k);if(old?.fill)old.fill(0);this._fatCache.delete(k);}}return b[within];}
  async nextCluster(cluster){
    if(cluster<2||cluster>=this.info.clusterCount+2)throw new Error('Cadeia FAT aponta para cluster inválido.');
    if(this.info.type==='FAT12'){const off=cluster+Math.floor(cluster/2),a=await this.fatByte(off),b=await this.fatByte(off+1),v=(cluster&1)?(((a>>4)|(b<<4))&0x0fff):(a|((b&0x0f)<<8));return v;}
    if(this.info.type==='FAT16'){const off=cluster*2;return (await this.fatByte(off))|((await this.fatByte(off+1))<<8);}
    const off=cluster*4;return ((await this.fatByte(off))|((await this.fatByte(off+1))<<8)|((await this.fatByte(off+2))<<16)|((await this.fatByte(off+3))<<24))&0x0fffffff;
  }
  clusterOffset(cluster){if(cluster<2||cluster>=this.info.clusterCount+2)throw new Error('Cluster fora do intervalo FAT.');return this.dataOffset+(cluster-2)*this.clusterSize;}
  async clusterChain(first,maxBytes=MAX_EXPORT_BYTES){
    if(first<2)return [];const out=[],seen=new Set();let c=first,bytes=0;
    while(!this.isEoc(c)){if(c===0||c===1||this.isBad(c)||c>=0x0ffffff0)throw new Error('Cadeia FAT corrompida.');if(seen.has(c))throw new Error('Ciclo detectado na cadeia FAT.');seen.add(c);out.push(c);bytes+=this.clusterSize;if(out.length>MAX_CHAIN_CLUSTERS||bytes>maxBytes+this.clusterSize)throw new Error('Cadeia FAT excede o limite de segurança.');const n=await this.nextCluster(c);if(this.isEoc(n))break;c=n;}
    return out;
  }
  async readDirectory(locator=null){
    const cluster=locator&&typeof locator==='object'?locator.firstCluster:locator;
    let raw;
    if(cluster===null&&this.info.type!=='FAT32')raw=await this.volume.read(this.rootDirOffset,this.info.rootDirSectors*this.info.bps);
    else{const first=cluster??this.info.rootCluster,chain=await this.clusterChain(first,MAX_DIR_BYTES);raw=new Uint8Array(chain.length*this.clusterSize);let p=0;for(const c of chain){const x=await this.volume.read(this.clusterOffset(c),this.clusterSize);raw.set(x,p);p+=x.length;}}
    const result=[];let lfn=[];
    for(let o=0;o+32<=raw.length;o+=32){const e=raw.subarray(o,o+32),first=e[0];if(first===0x00)break;if(first===0xe5){lfn=[];continue;}const attr=e[11];if(attr===0x0f){const ord=e[0]&0x1f;if(!ord||ord>20){lfn=[];continue;}if(e[0]&0x40)lfn=[];lfn.push({ord,text:lfnPiece(e),checksum:e[13]});continue;}if(attr&0x08){lfn=[];continue;}
      let name;const shortName=e.subarray(0,11);const validLfn=lfn.length&&lfn.every(x=>x.checksum===lfn[0].checksum)&&lfn[0].checksum===lfnChecksum(shortName)&&new Set(lfn.map(x=>x.ord)).size===lfn.length;
      if(validLfn)name=lfn.sort((a,b)=>a.ord-b.ord).map(x=>x.text).join('');else name=decodeDosName(e);lfn=[];name=safeName(name);if(name==='.'||name==='..')continue;
      const hi=u16(e,20),lo=u16(e,26),firstCluster=((hi<<16)|lo)>>>0,size=u32(e,28),isDirectory=!!(attr&0x10),modified=dosDateTime(u16(e,24),u16(e,22));result.push({name,size,isDirectory,firstCluster,modified,attributes:attr});
    }
    return result.sort((a,b)=>Number(b.isDirectory)-Number(a.isDirectory)||a.name.localeCompare(b.name,'pt-BR'));
  }
  async readFile(entry){
    if(entry.isDirectory)throw new Error('O item selecionado é uma pasta.');if(entry.size>MAX_EXPORT_BYTES)throw new Error('Arquivo grande demais para exportação segura nesta versão.');if(entry.size===0)return new Uint8Array(0);if(entry.firstCluster<2)throw new Error('Arquivo FAT sem cluster inicial válido.');
    const chain=await this.clusterChain(entry.firstCluster,entry.size);const out=new Uint8Array(entry.size);let p=0;for(const c of chain){if(p>=out.length)break;const x=await this.volume.read(this.clusterOffset(c),Math.min(this.clusterSize,out.length-p));out.set(x,p);p+=x.length;}if(p<out.length)throw new Error('Arquivo FAT truncado.');return out;
  }
  close(){for(const b of this._fatCache.values())if(b?.fill)b.fill(0);this._fatCache.clear();this.volume=null;}
}
