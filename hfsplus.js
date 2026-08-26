// Leitor somente-leitura de HFS+ / HFSX (Mac OS Extended) sobre uma fonte
// de bytes com acesso aleatório: `volume.read(offset, length) -> Uint8Array`.
//
// Existe porque o VeraCrypt do macOS costuma formatar o container como
// "Mac OS Extended". Até a 1.9.0 o Meu Cofre só entendia FAT/exFAT e
// mostrava "sistema de arquivos não suportado" nesses volumes.
//
// Cobertura: cabeçalho do volume, B-tree do catálogo, extents em linha e
// extents overflow, forks de dados, nomes UTF-16BE decompostos e datas.
// Fora do escopo: escrita, compressão HFS+ (decmpfs), forks de recurso,
// links rígidos e APFS.

const HFS_EPOCH_OFFSET = 2082844800; // 1904-01-01 -> 1970-01-01, em segundos
const NODE_DESCRIPTOR_SIZE = 14;
const MAX_NODE_SIZE = 64 * 1024;
const MAX_EXPORT_BYTES = 128 * 1024 * 1024;
const MAX_DIR_ENTRIES = 65536;
const MAX_LEAF_WALK = 8192;
const MAX_EXTENTS = 8192;
const CNID_ROOT_FOLDER = 2;
const CNID_EXTENTS = 3;
const CNID_CATALOG = 4;

function be16(b, o) { return (b[o] << 8) | b[o + 1]; }
function be32(b, o) { return ((b[o] * 0x1000000) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]) >>> 0; }
function be64(b, o) {
  let n = 0n;
  for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(b[o + i]);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Campo HFS+ de 64 bits grande demais para este navegador.');
  return Number(n);
}
function hfsDate(seconds) {
  if (!seconds) return null;
  const ms = (seconds - HFS_EPOCH_OFFSET) * 1000;
  if (!Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
function decodeHfsName(bytes, offset, charCount) {
  const codes = [];
  for (let i = 0; i < charCount; i++) codes.push(be16(bytes, offset + i * 2));
  let name = '';
  for (let i = 0; i < codes.length; i += 1024) name += String.fromCharCode(...codes.slice(i, i + 1024));
  // No catálogo do HFS+, "/" é gravado como ":". Os nomes também vêm decompostos.
  name = name.replace(/:/g, '/');
  try { name = name.normalize('NFC'); } catch { /* Safari 10+ sempre tem normalize */ }
  return name.replace(/[\u0000-\u001f\u007f]/g, '').trim() || 'Sem nome';
}
function readForkData(bytes, offset) {
  const extents = [];
  for (let i = 0; i < 8; i++) {
    const startBlock = be32(bytes, offset + 16 + i * 8);
    const blockCount = be32(bytes, offset + 20 + i * 8);
    if (blockCount) extents.push({ startBlock, blockCount });
  }
  return {
    logicalSize: be64(bytes, offset),
    clumpSize: be32(bytes, offset + 8),
    totalBlocks: be32(bytes, offset + 12),
    extents
  };
}

export async function openHfsPlus(volume) {
  if (volume.size < 2048) throw new Error('Volume pequeno demais para conter um HFS+.');
  const header = await volume.read(1024, 512);
  const signature = be16(header, 0);
  if (signature === 0x4244) {
    throw new Error('Este volume usa o HFS antigo (ou um wrapper HFS). Reformate como Mac OS Extended (HFS+) ou exFAT.');
  }
  if (signature !== 0x482b && signature !== 0x4858) throw new Error('O sistema de arquivos não é HFS+/HFSX.');
  const version = be16(header, 2);
  if (version !== 4 && version !== 5) throw new Error(`Versão de HFS+ não suportada (${version}).`);
  const blockSize = be32(header, 40);
  const totalBlocks = be32(header, 44);
  if (blockSize < 512 || blockSize > 1024 * 1024 || (blockSize & (blockSize - 1)) !== 0) throw new Error('Tamanho de bloco HFS+ inválido.');
  if (!totalBlocks) throw new Error('HFS+ sem blocos de alocação.');
  if (totalBlocks * blockSize > volume.size) throw new Error('O HFS+ declara um tamanho maior que o volume descriptografado.');
  const attributes = be32(header, 4);
  const info = {
    type: signature === 0x4858 ? 'HFSX (Mac OS Extended, sensível a maiúsculas)' : 'HFS+ (Mac OS Extended)',
    signature, version, blockSize, totalBlocks,
    freeBlocks: be32(header, 48),
    fileCount: be32(header, 32),
    folderCount: be32(header, 36),
    journaled: Boolean(attributes & 0x00002000),
    createdAt: hfsDate(be32(header, 16)),
    modifiedAt: hfsDate(be32(header, 20)),
    extentsFork: readForkData(header, 192),
    catalogFork: readForkData(header, 272)
  };
  if (!info.catalogFork.extents.length) throw new Error('HFS+ sem arquivo de catálogo utilizável.');
  const fs = new HfsPlusFileSystem(volume, info);
  await fs.open();
  return fs;
}

/** Fork (arquivo) do HFS+ visto como um espaço linear de bytes. */
class HfsFork {
  constructor(fs, fork, cnid, forkType = 0) {
    this.fs = fs; this.cnid = cnid; this.forkType = forkType;
    this.logicalSize = fork.logicalSize;
    this.totalBlocks = fork.totalBlocks;
    this.extents = fork.extents.slice();
    this.resolvedBlocks = this.extents.reduce((sum, e) => sum + e.blockCount, 0);
  }
  async ensureExtents(neededBlocks) {
    if (this.resolvedBlocks >= neededBlocks || this.resolvedBlocks >= this.totalBlocks) return;
    const more = await this.fs.lookupOverflowExtents(this.cnid, this.forkType, this.resolvedBlocks, neededBlocks);
    for (const e of more) {
      if (!e.blockCount) continue;
      this.extents.push(e);
      this.resolvedBlocks += e.blockCount;
      if (this.extents.length > MAX_EXTENTS) throw new Error('Arquivo HFS+ com fragmentação acima do limite seguro.');
    }
  }
  async read(offset, length) {
    if (length <= 0) return new Uint8Array(0);
    const blockSize = this.fs.info.blockSize;
    const lastBlock = Math.floor((offset + length - 1) / blockSize) + 1;
    await this.ensureExtents(lastBlock);
    const out = new Uint8Array(length);
    let written = 0, cursor = 0;
    for (const extent of this.extents) {
      const extentBytes = extent.blockCount * blockSize;
      const extentEnd = cursor + extentBytes;
      if (extentEnd > offset && cursor < offset + length) {
        const from = Math.max(offset, cursor);
        const to = Math.min(offset + length, extentEnd);
        const abs = extent.startBlock * blockSize + (from - cursor);
        if (abs + (to - from) > this.fs.volume.size) throw new Error('Extent HFS+ aponta fora do volume.');
        const chunk = await this.fs.volume.read(abs, to - from);
        out.set(chunk, from - offset);
        written += chunk.length;
      }
      cursor = extentEnd;
      if (cursor >= offset + length) break;
    }
    if (written < length) throw new Error('Arquivo HFS+ truncado ou com extents ausentes.');
    return out;
  }
}

/** B-tree genérica do HFS+ (catálogo e extents overflow). */
class HfsBTree {
  constructor(fork, name) { this.fork = fork; this.name = name; this._cache = new Map(); }
  async open() {
    const head = await this.fork.read(0, 512);
    if (((head[8] << 24) >> 24) !== 1) throw new Error(`Nó de cabeçalho da B-tree ${this.name} inválido.`);
    const h = NODE_DESCRIPTOR_SIZE;
    this.treeDepth = be16(head, h);
    this.rootNode = be32(head, h + 2);
    this.leafRecords = be32(head, h + 6);
    this.firstLeafNode = be32(head, h + 10);
    this.lastLeafNode = be32(head, h + 14);
    this.nodeSize = be16(head, h + 18);
    this.maxKeyLength = be16(head, h + 20);
    this.totalNodes = be32(head, h + 22);
    this.keyCompareType = head[h + 41];
    if (this.nodeSize < 512 || this.nodeSize > MAX_NODE_SIZE || (this.nodeSize & (this.nodeSize - 1)) !== 0) {
      throw new Error(`Tamanho de nó inválido na B-tree ${this.name}.`);
    }
    if (!this.totalNodes) throw new Error(`B-tree ${this.name} vazia.`);
  }
  async node(index) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.totalNodes) throw new Error(`Nó ${index} fora da B-tree ${this.name}.`);
    const hit = this._cache.get(index);
    if (hit) return hit;
    const bytes = await this.fork.read(index * this.nodeSize, this.nodeSize);
    const numRecords = be16(bytes, 10);
    if (numRecords * 2 + 2 > this.nodeSize - NODE_DESCRIPTOR_SIZE) throw new Error(`Contagem de registros inválida na B-tree ${this.name}.`);
    const offsets = [];
    for (let i = 0; i <= numRecords; i++) offsets.push(be16(bytes, this.nodeSize - 2 * (i + 1)));
    for (let i = 0; i < numRecords; i++) {
      if (offsets[i] < NODE_DESCRIPTOR_SIZE || offsets[i] > this.nodeSize) throw new Error(`Deslocamento inválido na B-tree ${this.name}.`);
    }
    const node = {
      bytes,
      fLink: be32(bytes, 0),
      bLink: be32(bytes, 4),
      kind: (bytes[8] << 24) >> 24,
      height: bytes[9],
      numRecords,
      offsets
    };
    this._cache.set(index, node);
    if (this._cache.size > 48) {
      const first = this._cache.keys().next().value;
      this._cache.get(first)?.bytes?.fill?.(0);
      this._cache.delete(first);
    }
    return node;
  }
  record(node, index) {
    const start = node.offsets[index];
    const end = node.offsets[index + 1] ?? this.nodeSize;
    if (end <= start) throw new Error(`Registro vazio na B-tree ${this.name}.`);
    const keyLength = be16(node.bytes, start);
    if (keyLength < 2 || keyLength > this.maxKeyLength || start + 2 + keyLength > end) throw new Error(`Chave inválida na B-tree ${this.name}.`);
    let dataStart = start + 2 + keyLength;
    if (dataStart & 1) dataStart += 1; // os registros ficam alinhados em 2 bytes
    return { keyOffset: start + 2, keyLength, dataOffset: dataStart, dataEnd: end, bytes: node.bytes };
  }
  /** Desce até a folha onde a chave procurada começaria. `compare(rec) <= 0` = registro antes/igual à busca. */
  async descend(compare) {
    if (!this.treeDepth) return this.firstLeafNode;
    let index = this.rootNode;
    let guard = 0;
    while (guard++ < 64) {
      const node = await this.node(index);
      if (node.kind === -1) return index;
      if (node.kind !== 0) throw new Error(`Nó inesperado durante a busca na B-tree ${this.name}.`);
      if (!node.numRecords) throw new Error(`Nó de índice vazio na B-tree ${this.name}.`);
      let child = null;
      for (let i = 0; i < node.numRecords; i++) {
        const rec = this.record(node, i);
        if (compare(rec) <= 0) child = be32(rec.bytes, rec.dataOffset);
        else break;
      }
      if (child === null) child = be32(this.record(node, 0).bytes, this.record(node, 0).dataOffset);
      index = child;
    }
    throw new Error(`Profundidade excessiva na B-tree ${this.name}.`);
  }
  close() {
    for (const node of this._cache.values()) node?.bytes?.fill?.(0);
    this._cache.clear();
  }
}

export class HfsPlusFileSystem {
  constructor(volume, info) { this.volume = volume; this.info = info; this.catalog = null; this.extentsTree = null; }
  async open() {
    // O catálogo pode depender do extents overflow, mas o overflow nunca depende de si mesmo.
    if (this.info.extentsFork.extents.length) {
      const extentsFork = new HfsFork(this, this.info.extentsFork, CNID_EXTENTS, 0);
      const tree = new HfsBTree(extentsFork, 'extents');
      try { await tree.open(); this.extentsTree = tree; } catch { this.extentsTree = null; }
    }
    this.catalog = new HfsBTree(new HfsFork(this, this.info.catalogFork, CNID_CATALOG, 0), 'catálogo');
    await this.catalog.open();
  }
  /** Extents adicionais de um fork muito fragmentado. */
  async lookupOverflowExtents(cnid, forkType, haveBlocks, neededBlocks) {
    if (!this.extentsTree || !cnid) return [];
    const tree = this.extentsTree;
    const cmp = (rec) => {
      const b = rec.bytes, o = rec.keyOffset;
      const recFork = b[o];
      const recCnid = be32(b, o + 2);
      const recStart = be32(b, o + 6);
      if (recCnid !== cnid) return recCnid < cnid ? -1 : 1;
      if (recFork !== forkType) return recFork < forkType ? -1 : 1;
      return recStart < haveBlocks ? -1 : recStart > haveBlocks ? 1 : 0;
    };
    const out = [];
    let nodeIndex = await tree.descend(cmp);
    let guard = 0, resolved = haveBlocks;
    while (nodeIndex && guard++ < MAX_LEAF_WALK) {
      const node = await tree.node(nodeIndex);
      if (node.kind !== -1) break;
      for (let i = 0; i < node.numRecords; i++) {
        const rec = tree.record(node, i);
        const b = rec.bytes, o = rec.keyOffset;
        const recCnid = be32(b, o + 2);
        if (recCnid > cnid) return out;
        if (recCnid !== cnid || b[o] !== forkType || be32(b, o + 6) < resolved) continue;
        for (let e = 0; e < 8; e++) {
          const startBlock = be32(b, rec.dataOffset + e * 8);
          const blockCount = be32(b, rec.dataOffset + 4 + e * 8);
          if (!blockCount) continue;
          out.push({ startBlock, blockCount });
          resolved += blockCount;
        }
        if (resolved >= neededBlocks) return out;
      }
      nodeIndex = node.fLink;
    }
    return out;
  }
  /** Lista o conteúdo de uma pasta. `locator` nulo = raiz. */
  async readDirectory(locator = null) {
    const parentId = locator && typeof locator === 'object' ? locator.cnid : (locator || CNID_ROOT_FOLDER);
    const tree = this.catalog;
    // Comparação apenas pelo parentID: o thread record da pasta tem nome vazio,
    // portanto é sempre o primeiro registro daquele parentID.
    const cmp = (rec) => {
      const recParent = be32(rec.bytes, rec.keyOffset);
      if (recParent !== parentId) return recParent < parentId ? -1 : 1;
      return be16(rec.bytes, rec.keyOffset + 4) === 0 ? 0 : 1;
    };
    const out = [];
    let nodeIndex = await tree.descend(cmp);
    let guard = 0;
    while (nodeIndex && guard++ < MAX_LEAF_WALK) {
      const node = await tree.node(nodeIndex);
      if (node.kind !== -1) break;
      for (let i = 0; i < node.numRecords; i++) {
        const rec = tree.record(node, i);
        const recParent = be32(rec.bytes, rec.keyOffset);
        if (recParent < parentId) continue;
        if (recParent > parentId) return this._sort(out);
        const charCount = be16(rec.bytes, rec.keyOffset + 4);
        if (rec.keyOffset + 6 + charCount * 2 > rec.dataEnd) continue;
        const recordType = be16(rec.bytes, rec.dataOffset);
        if (recordType === 3 || recordType === 4) continue; // thread records
        const name = decodeHfsName(rec.bytes, rec.keyOffset + 6, charCount);
        if (name === '.' || name === '..') continue;
        if (recordType === 1) {
          out.push({
            name, isDirectory: true, size: 0,
            cnid: be32(rec.bytes, rec.dataOffset + 8),
            valence: be32(rec.bytes, rec.dataOffset + 4),
            modified: hfsDate(be32(rec.bytes, rec.dataOffset + 16))
          });
        } else if (recordType === 2) {
          const dataFork = readForkData(rec.bytes, rec.dataOffset + 88);
          const resourceFork = readForkData(rec.bytes, rec.dataOffset + 168);
          out.push({
            name, isDirectory: false,
            size: dataFork.logicalSize,
            cnid: be32(rec.bytes, rec.dataOffset + 8),
            modified: hfsDate(be32(rec.bytes, rec.dataOffset + 16)),
            fork: dataFork,
            hasResourceFork: resourceFork.logicalSize > 0,
            hasAttributes: (be16(rec.bytes, rec.dataOffset + 2) & 0x0004) !== 0
          });
        }
        if (out.length > MAX_DIR_ENTRIES) throw new Error('Pasta HFS+ com número de itens acima do limite seguro.');
      }
      nodeIndex = node.fLink;
    }
    return this._sort(out);
  }
  _sort(list) {
    return list.sort((a, b) => Number(b.isDirectory) - Number(a.isDirectory) || a.name.localeCompare(b.name, 'pt-BR'));
  }
  async readFile(entry) {
    if (!entry || entry.isDirectory) throw new Error('O item selecionado é uma pasta.');
    const size = Number(entry.size || 0);
    if (size > MAX_EXPORT_BYTES) throw new Error('Arquivo grande demais para exportação segura nesta versão (limite: 128 MB).');
    if (size === 0) {
      if (entry.hasResourceFork || entry.hasAttributes) {
        throw new Error('Este arquivo guarda o conteúdo em fork de recurso ou em compressão HFS+, que esta versão não lê. Exporte-o pelo Finder com o volume montado.');
      }
      return new Uint8Array(0);
    }
    const fork = new HfsFork(this, entry.fork, entry.cnid, 0);
    return fork.read(0, size);
  }
  close() {
    this.catalog?.close();
    this.extentsTree?.close();
    this.catalog = null; this.extentsTree = null; this.volume = null;
  }
}
