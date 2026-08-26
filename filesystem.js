import { openFat } from './fat.js';
import { openExFat } from './exfat.js';
import { openHfsPlus } from './hfsplus.js';

const ascii = (bytes) => String.fromCharCode(...bytes);

/** Sistemas de arquivos que o leitor interno entende, em ordem de detecção. */
export const SUPPORTED_FILE_SYSTEMS = Object.freeze([
  'HFS+ / HFSX (Mac OS Extended) — o padrão do VeraCrypt no macOS',
  'exFAT',
  'FAT32 / FAT16 / FAT12 (com nomes longos e nomes 8.3 em minúsculas)'
]);

export async function openSupportedFileSystem(volume) {
  // O cabeçalho do volume HFS+ fica no bloco 1024; exFAT e FAT ficam no setor 0.
  const boot = await volume.read(0, 512);
  if (ascii(boot.subarray(3, 11)) === 'EXFAT   ') return openExFat(volume);

  if (volume.size >= 2048) {
    const hfsHeader = await volume.read(1024, 2);
    const signature = (hfsHeader[0] << 8) | hfsHeader[1];
    if (signature === 0x482b || signature === 0x4858 || signature === 0x4244) return openHfsPlus(volume);
  }

  // APFS: o superbloco do container começa com nx_magic 'NXSB' no offset 32.
  if (ascii(boot.subarray(32, 36)) === 'NXSB') {
    throw new Error('Este container está formatado em APFS, que esta versão não lê. Monte-o no Mac pelo VeraCrypt oficial, ou reformate como Mac OS Extended (HFS+) ou exFAT para poder abri-lo também no iPhone.');
  }

  const looksLikeFat = boot[510] === 0x55 && boot[511] === 0xaa && (boot[0] === 0xeb || boot[0] === 0xe9 || boot[0] === 0xe8);
  if (!looksLikeFat && boot[510] !== 0x55) {
    throw new Error('O cabeçalho VeraCrypt abriu, mas não foi encontrado um sistema de arquivos reconhecível. Volumes criados com “sem sistema de arquivos” só podem ser usados após formatação, e o APFS não é lido nesta versão.');
  }
  return openFat(volume);
}
