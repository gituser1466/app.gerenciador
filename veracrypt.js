import { concatBytes, randomBytes, wipe } from './utils.js';

// VeraCrypt-compatible file-container reader.
// Scope intentionally narrow for safety and portability in a PWA:
// - non-system file containers
// - normal or hidden volume header
// - AES-256-XTS
// - PBKDF2-HMAC-SHA-512 / SHA-256
// - password + ordinary keyfiles + PIM
// Filesystems are handled separately by fat.js.

const HEADER_SIZE = 512;
const SALT_SIZE = 64;
const ENCRYPTED_HEADER_SIZE = 448;
const HIDDEN_HEADER_OFFSET = 64 * 1024;
const DATA_UNIT = 512;
const MAX_KEYFILE_BYTES = 1024 * 1024;
const MAX_PASSWORD_BYTES = 128;
const MAX_KEYFILES = 32;
const MAX_PIM = 20000;
const MAGIC = new Uint8Array([0x56, 0x45, 0x52, 0x41]); // VERA

const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);
const INV_SBOX = new Uint8Array([
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
]);
const RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);

function expandAes256(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('Chave AES inválida.');
  const out = new Uint8Array(240); out.set(key);
  const temp = new Uint8Array(4); let used = 32, rc = 0;
  while (used < out.length) {
    temp.set(out.subarray(used - 4, used));
    if (used % 32 === 0) {
      const t = temp[0]; temp[0]=SBOX[temp[1]]; temp[1]=SBOX[temp[2]]; temp[2]=SBOX[temp[3]]; temp[3]=SBOX[t]; temp[0]^=RCON[rc++];
    } else if (used % 32 === 16) {
      for (let i=0;i<4;i++) temp[i]=SBOX[temp[i]];
    }
    for (let i=0;i<4 && used<out.length;i++,used++) out[used]=out[used-32]^temp[i];
  }
  wipe(temp); return out;
}
function xtime(a){ return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 255; }
function mul(a,b){ let p=0,x=a,y=b; for(let i=0;i<8;i++){ if(y&1)p^=x; const hi=x&0x80; x=(x<<1)&255; if(hi)x^=0x1b; y>>>=1; } return p; }
function addRoundKey(s,exp,round){ const o=round*16; for(let i=0;i<16;i++)s[i]^=exp[o+i]; }
function shiftRows(s){ const t=s.slice(); s[0]=t[0];s[1]=t[5];s[2]=t[10];s[3]=t[15];s[4]=t[4];s[5]=t[9];s[6]=t[14];s[7]=t[3];s[8]=t[8];s[9]=t[13];s[10]=t[2];s[11]=t[7];s[12]=t[12];s[13]=t[1];s[14]=t[6];s[15]=t[11]; wipe(t); }
function invShiftRows(s){ const t=s.slice(); s[0]=t[0];s[1]=t[13];s[2]=t[10];s[3]=t[7];s[4]=t[4];s[5]=t[1];s[6]=t[14];s[7]=t[11];s[8]=t[8];s[9]=t[5];s[10]=t[2];s[11]=t[15];s[12]=t[12];s[13]=t[9];s[14]=t[6];s[15]=t[3]; wipe(t); }
function mixColumns(s){ for(let c=0;c<4;c++){ const i=c*4,a=s[i],b=s[i+1],d=s[i+2],e=s[i+3],x=a^b^d^e; s[i]=a^x^xtime(a^b);s[i+1]=b^x^xtime(b^d);s[i+2]=d^x^xtime(d^e);s[i+3]=e^x^xtime(e^a); } }
function invMixColumns(s){ for(let c=0;c<4;c++){ const i=c*4,a=s[i],b=s[i+1],d=s[i+2],e=s[i+3]; s[i]=mul(a,14)^mul(b,11)^mul(d,13)^mul(e,9); s[i+1]=mul(a,9)^mul(b,14)^mul(d,11)^mul(e,13); s[i+2]=mul(a,13)^mul(b,9)^mul(d,14)^mul(e,11); s[i+3]=mul(a,11)^mul(b,13)^mul(d,9)^mul(e,14); } }
function aesEncryptBlock(block, exp){ const s=new Uint8Array(block); addRoundKey(s,exp,0); for(let r=1;r<14;r++){ for(let i=0;i<16;i++)s[i]=SBOX[s[i]]; shiftRows(s); mixColumns(s); addRoundKey(s,exp,r); } for(let i=0;i<16;i++)s[i]=SBOX[s[i]]; shiftRows(s); addRoundKey(s,exp,14); return s; }
function aesDecryptBlock(block, exp){ const s=new Uint8Array(block); addRoundKey(s,exp,14); for(let r=13;r>=1;r--){ invShiftRows(s); for(let i=0;i<16;i++)s[i]=INV_SBOX[s[i]]; addRoundKey(s,exp,r); invMixColumns(s); } invShiftRows(s); for(let i=0;i<16;i++)s[i]=INV_SBOX[s[i]]; addRoundKey(s,exp,0); return s; }
function unitTweak(unitNo){ let n=BigInt(unitNo); const b=new Uint8Array(16); for(let i=0;i<8;i++){ b[i]=Number(n&255n); n>>=8n; } return b; }
function mulAlphaLE(t){ let carry=0; for(let i=0;i<16;i++){ const next=(t[i]>>>7)&1; t[i]=((t[i]<<1)&255)|carry; carry=next; } if(carry)t[0]^=0x87; }

export function aesXtsTransformForTest(data, key1, key2, startDataUnitNo = 0, decrypt = false, startCipherBlockNo = 0) {
  return aesXtsTransform(data,key1,key2,startDataUnitNo,decrypt,startCipherBlockNo);
}
function aesXtsTransform(data,key1,key2,startDataUnitNo=0,decrypt=false,startCipherBlockNo=0){
  if (!(data instanceof Uint8Array) || data.length % 16) throw new Error('XTS exige blocos de 16 bytes.');
  if (!Number.isSafeInteger(Number(startDataUnitNo)) || Number(startDataUnitNo)<0) throw new Error('Número de unidade XTS inválido.');
  if (!Number.isInteger(startCipherBlockNo)||startCipherBlockNo<0||startCipherBlockNo>=32) throw new Error('Bloco inicial XTS inválido.');
  const e1=expandAes256(key1),e2=expandAes256(key2),out=new Uint8Array(data.length); let pos=0,unit=BigInt(startDataUnitNo),startBlock=startCipherBlockNo;
  try{
    while(pos<data.length){
      const ti=unitTweak(unit), tweak=aesEncryptBlock(ti,e2); wipe(ti);
      for(let j=0;j<startBlock;j++)mulAlphaLE(tweak);
      let block=startBlock;
      while(block<32 && pos<data.length){
        const x=new Uint8Array(16); for(let i=0;i<16;i++)x[i]=data[pos+i]^tweak[i];
        const y=decrypt?aesDecryptBlock(x,e1):aesEncryptBlock(x,e1); for(let i=0;i<16;i++)out[pos+i]=y[i]^tweak[i]; wipe(x);wipe(y);mulAlphaLE(tweak);pos+=16;block++;
      }
      wipe(tweak); unit++; startBlock=0;
    }
    return out;
  } finally { wipe(e1);wipe(e2); }
}

let CRC_TABLE=null;
function crcTable(){ if(CRC_TABLE)return CRC_TABLE; CRC_TABLE=new Uint32Array(256); for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?(0xedb88320^(c>>>1)):(c>>>1);CRC_TABLE[n]=c>>>0;}return CRC_TABLE; }
function crcUpdate(state,byte){ return (crcTable()[(state^byte)&255]^(state>>>8))>>>0; }
function crc32(bytes){ let c=0xffffffff; for(const b of bytes)c=crcUpdate(c,b); return (c^0xffffffff)>>>0; }

async function applyKeyfiles(password,keyfiles){
  const pass=new TextEncoder().encode(String(password??''));
  if(pass.length>MAX_PASSWORD_BYTES){wipe(pass);throw new Error('A senha excede 128 bytes em UTF-8, limite desta compatibilidade VeraCrypt.');}
  if(!keyfiles?.length)return pass;
  if(keyfiles.length>MAX_KEYFILES){wipe(pass);throw new Error(`Use no máximo ${MAX_KEYFILES} keyfiles por abertura.`);}
  const poolSize=pass.length<=64?64:128, pool=new Uint8Array(poolSize); pool.set(pass); wipe(pass);
  for(const file of keyfiles){
    let bytes;
    if(file instanceof Uint8Array){
      if(file.length<1)throw new Error('Keyfile vazio não é aceito.');
      bytes=file.slice(0,MAX_KEYFILE_BYTES);
    }else{
      if(!file || typeof file.slice!=='function')throw new Error('Keyfile inválido.');
      const len=Math.min(Number(file.size)||0,MAX_KEYFILE_BYTES); if(len<1)throw new Error('Keyfile vazio não é aceito.');
      bytes=new Uint8Array(await file.slice(0,len).arrayBuffer());
    }
    let state=0xffffffff,pos=0;
    try{
      for(const b of bytes){ state=crcUpdate(state,b); const v=[state>>>24,(state>>>16)&255,(state>>>8)&255,state&255]; for(const x of v){pool[pos]=(pool[pos]+x)&255;pos++;if(pos>=pool.length)pos=0;} }
    } finally { wipe(bytes); }
  }
  return pool;
}

async function deriveHeaderKey(passwordBytes,salt,pim,hash){
  const iterations=pim>0?15000+(pim*1000):500000;
  if(!Number.isSafeInteger(iterations)||iterations<16000||iterations>100000000)throw new Error('PIM produz uma contagem de iterações inválida/excessiva.');
  const base=await crypto.subtle.importKey('raw',passwordBytes,'PBKDF2',false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash,salt,iterations},base,512));
}
function be16(b,o){return (b[o]<<8)|b[o+1];}
function be32(b,o){return ((b[o]*0x1000000)+(b[o+1]<<16)+(b[o+2]<<8)+b[o+3])>>>0;}
function be64(b,o){let n=0n;for(let i=0;i<8;i++)n=(n<<8n)|BigInt(b[o+i]);if(n>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Campo de 64 bits grande demais para este navegador.');return Number(n);}
function equal4(a,b){return a[0]===b[0]&&a[1]===b[1]&&a[2]===b[2]&&a[3]===b[3];}
function parseDecryptedHeader(dec,fileSize,hash,pim,headerOffset){
  if(!equal4(dec,MAGIC))return null;
  const headerVersion=be16(dec,4),requiredVersion=be16(dec,6),keyAreaCrc=be32(dec,8),hiddenVolumeSize=be64(dec,28),volumeSize=be64(dec,36),encryptedAreaStart=be64(dec,44),encryptedAreaLength=be64(dec,52),flags=be32(dec,60),sectorSize=be32(dec,64),headerCrc=be32(dec,188);
  if(headerVersion<4||headerVersion>5)return null;
  if(crc32(dec.subarray(0,188))!==headerCrc)return null;
  if(crc32(dec.subarray(192,448))!==keyAreaCrc)return null;
  if(![512,1024,2048,4096].includes(sectorSize)||sectorSize%512!==0)throw new Error('Tamanho de setor VeraCrypt não suportado.');
  if(encryptedAreaStart<0||encryptedAreaLength<=0||encryptedAreaStart+encryptedAreaLength>fileSize)throw new Error('Cabeçalho VeraCrypt contém limites de volume inválidos.');
  const primary=dec.slice(192,224),secondary=dec.slice(224,256);
  let same=true;for(let i=0;i<32;i++)if(primary[i]!==secondary[i]){same=false;break;}if(same){wipe(primary);wipe(secondary);throw new Error('Volume rejeitado: chaves XTS primária e secundária são idênticas.');}
  return {cipher:'AES-256-XTS',hash,pim,iterations:pim>0?15000+pim*1000:500000,headerVersion,requiredVersion,hiddenVolumeSize,volumeSize,encryptedAreaStart,encryptedAreaLength,flags,sectorSize,headerOffset,primaryKey:primary,secondaryKey:secondary};
}
async function readHeaderMaterial(file,passwordBytes,{pim=0,hash='SHA-512',offset=0,source='primário'}={}){
  if(offset<0||file.size<offset+HEADER_SIZE)return null;
  const raw=new Uint8Array(await file.slice(offset,offset+HEADER_SIZE).arrayBuffer()), salt=raw.slice(0,SALT_SIZE); let hk=null,dec=null;
  try{
    hk=await deriveHeaderKey(passwordBytes,salt,pim,hash);
    dec=aesXtsTransform(raw.subarray(SALT_SIZE),hk.subarray(0,32),hk.subarray(32,64),0,true,0);
    const info=parseDecryptedHeader(dec,file.size,hash,pim,offset);
    if(!info)return null;
    info.headerSource=source;
    return {info,decryptedHeader:dec.slice()};
  } finally { wipe(raw);wipe(salt);hk&&wipe(hk);dec&&wipe(dec); }
}
async function tryHeader(file,passwordBytes,opts={}){
  const material=await readHeaderMaterial(file,passwordBytes,opts);
  if(!material)return null;
  try{return material.info;}finally{wipe(material.decryptedHeader);}
}

export async function openVeraCryptFile(file,{password='',pim=0,keyfiles=[],hash='auto',hidden=false}={}){
  if(!file||typeof file.slice!=='function')throw new Error('Selecione um arquivo-container VeraCrypt.');
  if(file.size<262144)throw new Error('O arquivo é pequeno demais para um volume VeraCrypt moderno.');
  pim=Number.parseInt(String(pim||0),10)||0; if(pim<0||pim>MAX_PIM)throw new Error(`PIM inválido ou acima do limite defensivo desta versão (${MAX_PIM}).`);
  const pass=await applyKeyfiles(password,keyfiles); const hashes=hash==='auto'?['SHA-512','SHA-256']:[hash]; let info=null;
  const primaryOffset=hidden?HIDDEN_HEADER_OFFSET:0,backupOffset=hidden?file.size-HIDDEN_HEADER_OFFSET:file.size-(2*HIDDEN_HEADER_OFFSET);
  try{
    for(const source of [{offset:primaryOffset,label:'primário'},{offset:backupOffset,label:'backup embutido'}]){
      if(source.offset===primaryOffset&&source.label!=='primário')continue;
      for(const h of hashes){ if(!['SHA-512','SHA-256'].includes(h))throw new Error('KDF não suportado nesta versão.'); info=await tryHeader(file,pass,{pim,hash:h,offset:source.offset,source:source.label}); if(info)break; }
      if(info)break;
    }
    if(!info)throw new Error('Não foi possível abrir o cabeçalho primário nem o backup embutido. Verifique senha, PIM, keyfiles, volume normal/oculto e KDF. Esta versão suporta AES-XTS com PBKDF2 SHA-512/SHA-256.');
    info.hidden=!!hidden;return new VeraCryptVolume(file,info);
  } finally {wipe(pass);}
}

function supportedHashList(hash){
  const value=String(hash||'auto');
  if(value==='auto')return ['SHA-512','SHA-256'];
  if(!['SHA-512','SHA-256'].includes(value))throw new Error('KDF não suportado para alteração local. Use SHA-512 ou SHA-256.');
  return [value];
}
function headerOffsets(fileSize,hidden){
  return hidden
    ? {primary:HIDDEN_HEADER_OFFSET,backup:fileSize-HIDDEN_HEADER_OFFSET}
    : {primary:0,backup:fileSize-(2*HIDDEN_HEADER_OFFSET)};
}
async function findHeaderMaterial(file,passwordBytes,{pim=0,hash='auto',hidden=false,source='any'}={}){
  const offsets=headerOffsets(file.size,!!hidden);
  const candidates=source==='backup'
    ? [{offset:offsets.backup,label:'backup embutido'}]
    : source==='primary'
      ? [{offset:offsets.primary,label:'primário'}]
      : [{offset:offsets.primary,label:'primário'},{offset:offsets.backup,label:'backup embutido'}];
  for(const candidate of candidates){
    for(const h of supportedHashList(hash)){
      const material=await readHeaderMaterial(file,passwordBytes,{pim,hash:h,offset:candidate.offset,source:candidate.label});
      if(material){material.info.hidden=!!hidden;return material;}
    }
  }
  return null;
}
async function encryptHeaderMaterial(decryptedHeader,passwordBytes,{pim=0,hash='SHA-512'}={}){
  if(!(decryptedHeader instanceof Uint8Array)||decryptedHeader.length!==ENCRYPTED_HEADER_SIZE)throw new Error('Cabeçalho descriptografado inválido.');
  if(!['SHA-512','SHA-256'].includes(hash))throw new Error('KDF de destino não suportado.');
  const salt=randomBytes(SALT_SIZE);let hk=null,enc=null;
  try{
    hk=await deriveHeaderKey(passwordBytes,salt,pim,hash);
    enc=aesXtsTransform(decryptedHeader,hk.subarray(0,32),hk.subarray(32,64),0,false,0);
    return concatBytes(salt,enc);
  } finally { wipe(salt);hk&&wipe(hk);enc&&wipe(enc); }
}
function patchedBlob(file,patches){
  const sorted=[...patches].sort((a,b)=>a.offset-b.offset);
  const parts=[];let cursor=0;
  for(const patch of sorted){
    if(!Number.isSafeInteger(patch.offset)||patch.offset<cursor||patch.offset+patch.bytes.length>file.size)throw new Error('Patch de cabeçalho fora dos limites.');
    if(patch.offset>cursor)parts.push(file.slice(cursor,patch.offset));
    parts.push(patch.bytes.slice());cursor=patch.offset+patch.bytes.length;
  }
  if(cursor<file.size)parts.push(file.slice(cursor));
  return new Blob(parts,{type:'application/octet-stream'});
}

export async function reencryptVeraCryptHeaders(file,current={},next={}){
  if(!file||typeof file.slice!=='function')throw new Error('Selecione um container VeraCrypt.');
  const currentPim=Number.parseInt(String(current.pim||0),10)||0;
  const nextPim=Number.parseInt(String(next.pim??currentPim),10)||0;
  if(currentPim<0||currentPim>MAX_PIM||nextPim<0||nextPim>MAX_PIM)throw new Error('PIM inválido.');
  const currentPass=await applyKeyfiles(current.password||'',current.keyfiles||[]);let nextPass=null,material=null,primary=null,backup=null;
  try{
    material=await findHeaderMaterial(file,currentPass,{pim:currentPim,hash:current.hash||'auto',hidden:!!current.hidden,source:'any'});
    if(!material)throw new Error('Credenciais atuais não abriram o cabeçalho VeraCrypt.');
    const targetHash=(next.hash==='same'||!next.hash||next.hash==='auto')?material.info.hash:next.hash;
    nextPass=await applyKeyfiles(next.password??current.password??'',next.keyfiles??current.keyfiles??[]);
    primary=await encryptHeaderMaterial(material.decryptedHeader,nextPass,{pim:nextPim,hash:targetHash});
    backup=await encryptHeaderMaterial(material.decryptedHeader,nextPass,{pim:nextPim,hash:targetHash});
    const offsets=headerOffsets(file.size,!!current.hidden);
    const blob=patchedBlob(file,[{offset:offsets.primary,bytes:primary},{offset:offsets.backup,bytes:backup}]);
    return {blob,info:{...material.info,hash:targetHash,pim:nextPim,iterations:nextPim>0?15000+nextPim*1000:500000,headerSource:'novo primário'}};
  } finally {
    wipe(currentPass);nextPass&&wipe(nextPass);material?.decryptedHeader&&wipe(material.decryptedHeader);primary&&wipe(primary);backup&&wipe(backup);
  }
}

export async function repairVeraCryptPrimaryHeader(file,credentials={}){
  if(!file||typeof file.slice!=='function')throw new Error('Selecione um container VeraCrypt.');
  const pim=Number.parseInt(String(credentials.pim||0),10)||0;if(pim<0||pim>MAX_PIM)throw new Error('PIM inválido.');
  const pass=await applyKeyfiles(credentials.password||'',credentials.keyfiles||[]);let material=null,fresh=null;
  try{
    material=await findHeaderMaterial(file,pass,{pim,hash:credentials.hash||'auto',hidden:!!credentials.hidden,source:'backup'});
    if(!material)throw new Error('O backup embutido não pôde ser aberto com as credenciais informadas.');
    fresh=await encryptHeaderMaterial(material.decryptedHeader,pass,{pim,hash:material.info.hash});
    const offsets=headerOffsets(file.size,!!credentials.hidden);
    return {blob:patchedBlob(file,[{offset:offsets.primary,bytes:fresh}]),info:{...material.info,headerSource:'primário reparado'}};
  } finally { wipe(pass);material?.decryptedHeader&&wipe(material.decryptedHeader);fresh&&wipe(fresh); }
}

export class VeraCryptVolume{
  constructor(file,info){this.file=file;this.info=info;this.closed=false;this._cache=new Map();this._cacheLimit=96;}
  get size(){return this.info.encryptedAreaLength;}
  async read(offset,length){
    if(this.closed)throw new Error('Volume VeraCrypt fechado.');
    offset=Number(offset);length=Number(length);if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(length)||offset<0||length<0||offset+length>this.info.encryptedAreaLength)throw new Error('Leitura fora dos limites do volume.');
    if(length===0)return new Uint8Array(0);
    const first=Math.floor(offset/DATA_UNIT),last=Math.floor((offset+length-1)/DATA_UNIT),out=new Uint8Array(length);let outPos=0;
    for(let unit=first;unit<=last;unit++){
      let plain=this._cache.get(unit); if(!plain){const absolute=this.info.encryptedAreaStart+unit*DATA_UNIT;const cipher=new Uint8Array(await this.file.slice(absolute,absolute+DATA_UNIT).arrayBuffer());if(cipher.length!==DATA_UNIT)throw new Error('Container truncado durante leitura.');plain=aesXtsTransform(cipher,this.info.primaryKey,this.info.secondaryKey,absolute/DATA_UNIT,true,0);wipe(cipher);this._cache.set(unit,plain);if(this._cache.size>this._cacheLimit){const k=this._cache.keys().next().value;const old=this._cache.get(k);old&&wipe(old);this._cache.delete(k);}}
      const unitStart=unit*DATA_UNIT,a=Math.max(offset,unitStart)-unitStart,b=Math.min(offset+length,unitStart+DATA_UNIT)-unitStart,chunk=plain.subarray(a,b);out.set(chunk,outPos);outPos+=chunk.length;
    }
    return out;
  }
  clearCache(){for(const b of this._cache.values())wipe(b);this._cache.clear();}
  close(){if(this.closed)return;this.clearCache();wipe(this.info.primaryKey);wipe(this.info.secondaryKey);this.file=null;this.closed=true;}
}
