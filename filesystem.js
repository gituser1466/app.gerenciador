import { openFat } from './fat.js';
import { openExFat } from './exfat.js';

export async function openSupportedFileSystem(volume){
  const boot=await volume.read(0,512);
  const sig=String.fromCharCode(...boot.subarray(3,11));
  if(sig==='EXFAT   ')return openExFat(volume);
  return openFat(volume);
}
