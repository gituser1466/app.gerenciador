// Read-only exFAT browser over a random-access decrypted byte source.
// Strictly bounded for mobile use; never writes to the selected container.

const MAX_CHAIN_CLUSTERS = 1_000_000;
const MAX_DIR_BYTES = 16 * 1024 * 1024;
const MAX_EXPORT_BYTES = 128 * 1024 * 1024;

function u16(b,o){return b[o]|(b[o+1]<<8);}
function u32(b,o){return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0;}
function u64(b,o){let n=0n;for(let i=7;i>=0;i--)n=(n<<8n)|BigInt(b[o+i]);if(n>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Campo exFAT grande demais para este navegador.');return Number(n);}
function ascii(bytes){return String.fromCharCode(...bytes);}
function cleanName(name){return String(name||'').replace(/[\u0000-\u001f]/g,'').trim()||'Sem nome';}
function setChecksum(entries){let sum=0;let pos=0;for(const e of entries){for(let i=0;i<32;i++,pos++){if(pos===2||pos===3)continue;sum=((((sum&1)?0x8000:0)+(sum>>>1)+e[i])&0xffff);}}return sum;}
function exfatDateTime(raw){
  if(!raw)return null;const time=raw&0xffff,date=raw>>>16;const day=date&31,month=(date>>>5)&15,year=1980+((date>>>9)&127),sec=(time&31)*2,min=(time>>>5)&63,hour=(time>>>11)&31;
  if(!day||!month)return null;const d=new Date(year,month-1,day,hour,min,sec);return Number.isNaN(d.getTime())?null:d.toISOString();
}
function decodeName(entries,nameLength){const codes=[];for(const e of entries){for(let o=2;o<32;o+=2){if(codes.length>=nameLength)break;codes.push(u16(e,o));}}return cleanName(String.fromCharCode(...codes));}

export async function openExFat(volume){
  const boot=await volume.read(0,512);
  if(ascii(boot.subarray(3,11))!=='EXFAT   ')throw new Error('O sistema de arquivos não é exFAT.');
  if(boot[510]!==0x55||boot[511]!==0xaa)throw new Error('Assinatura exFAT 0x55AA ausente.');
  const bpsShift=boot[108],spcShift=boot[109],fatCount=boot[110],bps=2**bpsShift,sectorsPerCluster=2**spcShift,clusterSize=bps*sectorsPerCluster;
  if(bpsShift<9||bpsShift>12||spcShift>25||clusterSize<512||clusterSize>32*1024*1024||fatCount<1||fatCount>2)throw new Error('Parâmetros exFAT inválidos.');
  const volumeLength=u64(boot,72),fatOffset=u32(boot,80),fatLength=u32(boot,84),heapOffset=u32(boot,88),clusterCount=u32(boot,92),rootCluster=u32(boot,96);
  if(!volumeLength||volumeLength*bps>volume.size)throw new Error('exFAT declara tamanho maior que o volume criptografado.');
  if(!fatOffset||!fatLength||!clusterCount||rootCluster<2||rootCluster>=clusterCount+2)throw new Error('Geometria exFAT inválida.');
  if((fatOffset+fatLength)*bps>volume.size||heapOffset*bps>volume.size)throw new Error('Estruturas exFAT fora dos limites do volume.');
  if(fatLength*bps<(clusterCount+2)*4)throw new Error('FAT exFAT menor que o número de clusters declarado.');
  if((heapOffset+clusterCount*sectorsPerCluster)*bps>volume.size)throw new Error('Cluster heap exFAT excede o volume.');
  return new ExFatFileSystem(volume,{type:'exFAT',bps,sectorsPerCluster,clusterSize,fatCount,volumeLength,fatOffset,fatLength,heapOffset,clusterCount,rootCluster});
}

export class ExFatFileSystem{
  constructor(volume,info){this.volume=volume;this.info=info;this.clusterSize=info.clusterSize;this.fatByteOffset=info.fatOffset*info.bps;this.heapByteOffset=info.heapOffset*info.bps;this._fatCache=new Map();}
  clusterOffset(cluster){if(cluster<2||cluster>=this.info.clusterCount+2)throw new Error('Cluster exFAT fora dos limites.');return this.heapByteOffset+(cluster-2)*this.clusterSize;}
  isEoc(v){return v>=0xfffffff8;}
  isBad(v){return v===0xfffffff7;}
  async fatSector(sec){let b=this._fatCache.get(sec);if(!b){b=await this.volume.read(this.fatByteOffset+sec*this.info.bps,this.info.bps);this._fatCache.set(sec,b);if(this._fatCache.size>32){const k=this._fatCache.keys().next().value,old=this._fatCache.get(k);old?.fill?.(0);this._fatCache.delete(k);}}return b;}
  async nextCluster(cluster){if(cluster<2||cluster>=this.info.clusterCount+2)throw new Error('Cluster exFAT inválido.');const off=cluster*4,sec=Math.floor(off/this.info.bps),within=off%this.info.bps;if(within<=this.info.bps-4){const b=await this.fatSector(sec);return u32(b,within);}const x=await this.volume.read(this.fatByteOffset+off,4);return u32(x,0);}
  async chain(first,maxBytes){if(first<2)return [];const out=[],seen=new Set();let c=first,total=0;while(!this.isEoc(c)){if(c===0||c===1||this.isBad(c)||c>=this.info.clusterCount+2)throw new Error('Cadeia exFAT corrompida.');if(seen.has(c))throw new Error('Ciclo detectado na cadeia exFAT.');seen.add(c);out.push(c);total+=this.clusterSize;if(out.length>MAX_CHAIN_CLUSTERS||total>maxBytes+this.clusterSize)throw new Error('Cadeia exFAT excede o limite de segurança.');const n=await this.nextCluster(c);if(this.isEoc(n))break;c=n;}return out;}
  contiguousClusters(first,length){const count=Math.ceil(length/this.clusterSize);if(count>MAX_CHAIN_CLUSTERS||first<2||first+count>this.info.clusterCount+2)throw new Error('Extensão contígua exFAT inválida.');return Array.from({length:count},(_,i)=>first+i);}
  async readEntryData(entry,maxBytes){
    const length=entry?Number(entry.dataLength||0):maxBytes;if(entry&&length>maxBytes)throw new Error('Item exFAT excede o limite de segurança.');
    const first=entry?entry.firstCluster:this.info.rootCluster;if(first<2)return new Uint8Array(0);
    const clusters=entry?.noFatChain?this.contiguousClusters(first,length):await this.chain(first,maxBytes);
    const target=entry?length:Math.min(clusters.length*this.clusterSize,maxBytes),out=new Uint8Array(target);let pos=0;
    for(const c of clusters){if(pos>=out.length)break;const take=Math.min(this.clusterSize,out.length-pos),x=await this.volume.read(this.clusterOffset(c),take);out.set(x,pos);pos+=x.length;}
    if(entry&&pos<length)throw new Error('Arquivo exFAT truncado.');return out;
  }
  async readDirectory(entry=null){
    let raw;if(entry){if(!entry.isDirectory)throw new Error('O item selecionado não é uma pasta.');if(entry.dataLength>MAX_DIR_BYTES)throw new Error('Diretório exFAT grande demais para leitura segura.');raw=await this.readEntryData(entry,MAX_DIR_BYTES);}else{const chain=await this.chain(this.info.rootCluster,MAX_DIR_BYTES);raw=new Uint8Array(Math.min(chain.length*this.clusterSize,MAX_DIR_BYTES));let p=0;for(const c of chain){if(p>=raw.length)break;const take=Math.min(this.clusterSize,raw.length-p),x=await this.volume.read(this.clusterOffset(c),take);raw.set(x,p);p+=x.length;}}
    const result=[];
    for(let o=0;o+32<=raw.length;){const primary=raw.subarray(o,o+32),type=primary[0];if(type===0x00)break;if(type!==0x85){o+=32;continue;}const secondaryCount=primary[1];if(secondaryCount<2||secondaryCount>18||o+(secondaryCount+1)*32>raw.length){o+=32;continue;}const set=[primary];for(let i=1;i<=secondaryCount;i++)set.push(raw.subarray(o+i*32,o+(i+1)*32));o+=(secondaryCount+1)*32;
      if(setChecksum(set)!==u16(primary,2))continue;const stream=set.find(e=>e[0]===0xc0),names=set.filter(e=>e[0]===0xc1);if(!stream||!names.length)continue;const nameLength=stream[3];if(!nameLength||nameLength>255)continue;const name=decodeName(names,nameLength);const attributes=u16(primary,4),isDirectory=!!(attributes&0x10),firstCluster=u32(stream,20),dataLength=u64(stream,24),validDataLength=u64(stream,8),noFatChain=!!(stream[1]&0x02),modified=exfatDateTime(u32(primary,12));
      if(dataLength>0&&(firstCluster<2||firstCluster>=this.info.clusterCount+2))continue;result.push({name,size:dataLength,isDirectory,firstCluster,dataLength,validDataLength,noFatChain,modified,attributes});
    }
    raw.fill(0);return result.sort((a,b)=>Number(b.isDirectory)-Number(a.isDirectory)||a.name.localeCompare(b.name,'pt-BR'));
  }
  async readFile(entry){if(entry.isDirectory)throw new Error('O item selecionado é uma pasta.');if(entry.dataLength>MAX_EXPORT_BYTES)throw new Error('Arquivo grande demais para exportação segura nesta versão (limite: 128 MB).');if(entry.dataLength===0)return new Uint8Array(0);return this.readEntryData(entry,MAX_EXPORT_BYTES);}
  close(){for(const b of this._fatCache.values())b?.fill?.(0);this._fatCache.clear();this.volume=null;}
}
