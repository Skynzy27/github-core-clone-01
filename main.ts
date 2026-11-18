// forge: a standalone GitHub-compatible git forge.
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL v4 and MCP
// from one in-memory store. Node 22, standard library only, no git binary, no network.
// Built for make.fun github-core-clone-01.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { createServer } from 'node:net';
import type { Socket } from 'node:net';

// -------------------------------------------------------------------------------------------
// constants
// -------------------------------------------------------------------------------------------

export const ZERO_OID = '0'.repeat(40);
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const VIEWER_IDENT = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
const DEFAULT_BRANCH = 'main';
const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';
// Fixed commit epoch: every timestamp the forge emits is deterministic, so a live run and
// its replay leave identical state.
const COMMIT_EPOCH = 1700000000;
const TRIAL_NOW = process.env.MAKEFUN_TRIAL_NOW ?? '2026-11-14T06:30:00.000Z';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const PKT_MAX = 65520;
const PACK_MAGIC = Buffer.from('PACK', 'ascii');
const SIDEBAND_ONE = Buffer.from([1]);

type Json = Record<string, unknown>;
type GitType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: GitType;
  data: Buffer;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

// -------------------------------------------------------------------------------------------
// small utilities
// -------------------------------------------------------------------------------------------

function sha1hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

function b64encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s/g, ''), 'base64');
}

function globalId(kind: string, key: string): string {
  return `${kind}_${createHash('sha1').update(key).digest('base64url')}`;
}

// -------------------------------------------------------------------------------------------
// pkt-line codec
// -------------------------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}

const PKT_FLUSH_BUF = Buffer.from('0000', 'ascii');

function pktFlush(): Buffer {
  // Shared: callers only ever pass it to Buffer.concat (which copies).
  return PKT_FLUSH_BUF;
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

interface PktDecoded {
  packets: Array<{ kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }>;
  rest: Buffer;
  ok: boolean;
}

/** Decode a whole buffer of pkt-lines. `rest` holds trailing bytes that are not pkt-lines. */
const EMPTY_BUFFER = Buffer.alloc(0);

function decodePktLines(buf: Buffer): PktDecoded {
  const packets: PktDecoded['packets'] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = Number.parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: EMPTY_BUFFER });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: EMPTY_BUFFER });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: EMPTY_BUFFER });
      off += 4;
      continue;
    }
    if (len < 4 || len > PKT_MAX || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, rest: buf.subarray(off), ok: off === buf.length || off + 4 > buf.length };
}

// -------------------------------------------------------------------------------------------
// git object model
// -------------------------------------------------------------------------------------------

function objectHeader(type: GitType, size: number): Buffer {
  return Buffer.from(`${type} ${size}\0`, 'utf8');
}

function hashObject(type: GitType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(objectHeader(type, data.length));
  h.update(data);
  return h.digest('hex');
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree entry');
    entries.push({
      mode: data.subarray(off, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const value = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, timestamp = COMMIT_EPOCH): Buffer {
  const who = `${VIEWER_IDENT} ${timestamp} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  return Buffer.from(`${lines.join('\n')}\n${msg}`, 'utf8');
}

interface TagView {
  object: string;
  type: GitType;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: (headers.get('type') ?? 'commit') as GitType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message,
  };
}

/** Every object reachable from `roots` (commit -> tree + parents, tag -> target, tree -> entries). */
function collectReachable(roots: Iterable<string>, lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (!object) throw new Error(`object ${oid} is missing from the store`);
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

// -------------------------------------------------------------------------------------------
// packfiles
// -------------------------------------------------------------------------------------------

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (off >= delta.length) throw new Error('delta size varint truncated');
      const byte = delta[off++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOff += delta[off++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[off++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOff + copySize > base.length || written + copySize > targetSize) throw new Error('delta copy out of range');
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (off + literal > delta.length || written + literal > targetSize) throw new Error('delta insert truncated');
      delta.copy(out, written, off, off + literal);
      off += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0 invalid');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

const PACK_TYPE: Record<number, GitType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const TYPE_CODE: Record<GitType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

/** The v2 capability advertisement never changes, so it is one shared buffer. */
const V2_ADVERTISEMENT = Buffer.concat([
  pktLine('version 2\n'),
  pktLine('ls-refs=unborn\n'),
  pktLine('fetch=shallow\n'),
  pktLine('object-format=sha1\n'),
  pktFlush(),
]);

interface PackRead {
  objects: Map<string, GitObject>;
  deltaCount: number;
}

/** Read a packfile (v2/v3), resolving OFS_DELTA and REF_DELTA entries. */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): PackRead {
  if (pack.length < 32) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack header missing');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version}`);
  const count = pack.readUInt32BE(8);
  // v5: compare trailer bytes directly instead of via two hex strings.
  const computed = createHash('sha1').update(pack.subarray(0, pack.length - 20)).digest();
  if (!pack.subarray(pack.length - 20).equals(computed)) throw new Error('pack trailer checksum mismatch');
  const objects = new Map<string, GitObject>();
  const byOffset = new Map<number, GitObject>();
  let deltaCount = 0;
  let off = 12;
  const readEntryHeader = (): { typeCode: number; size: number; next: number } => {
    const first = pack[off];
    let size = first & 0x0f;
    let shift = 4;
    let next = off + 1;
    let byte = first;
    while (byte & 0x80) {
      byte = pack[next++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    return { typeCode: (first >> 4) & 0x07, size, next };
  };
  const readOfsBase = (start: number): { baseOffset: number; next: number } => {
    let byte = pack[start];
    let next = start + 1;
    let value = byte & 0x7f;
    while (byte & 0x80) {
      byte = pack[next++];
      value = ((value + 1) * 128) + (byte & 0x7f);
    }
    return { baseOffset: value, next };
  };
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const { typeCode, size, next } = readEntryHeader();
    off = next;
    let baseObj: GitObject | undefined;
    let deltaData: Buffer | undefined;
    if (typeCode === 6) {
      const { baseOffset, next: after } = readOfsBase(off);
      off = after;
      baseObj = byOffset.get(entryOffset - baseOffset);
      if (!baseObj) throw new Error('ofs-delta base not found');
      deltaCount += 1;
    } else if (typeCode === 7) {
      const baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
      baseObj = objects.get(baseOid) ?? resolveBase?.(baseOid);
      if (!baseObj) throw new Error('ref-delta base not found');
      deltaCount += 1;
    }
    // inflate one zlib stream starting at off
    const view = pack.subarray(off);
    const inflated = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    const data: Buffer = inflated.buffer;
    off += inflated.engine.bytesWritten;
    let type: GitType;
    let content: Buffer;
    if (typeCode === 6 || typeCode === 7) {
      if (!baseObj) throw new Error('delta without base');
      type = baseObj.type;
      content = applyDelta(baseObj.data, data);
      deltaData = data;
      void deltaData;
    } else {
      type = PACK_TYPE[typeCode] as GitType;
      if (!type) throw new Error(`unknown pack entry type ${typeCode}`);
      content = data;
    }
    if (content.length !== size) throw new Error('pack entry size mismatch');
    const oid = hashObject(type, content);
    const obj: GitObject = { type, data: content };
    objects.set(oid, obj);
    byOffset.set(entryOffset, obj);
  }
  return { objects, deltaCount };
}

/** Write a packfile (v2, plain objects, no deltas) from an iterable of objects. */
function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(list.length, 8);
  parts.push(head);
  for (const obj of list) {
    const data = obj.data;
    const code = TYPE_CODE[obj.type];
    let size = data.length;
    const first = (code << 4) | (size & 0x0f);
    size >>= 4;
    const headerBytes: number[] = [first];
    while (size > 0) {
      let byte = size & 0x7f;
      size >>= 7;
      if (size > 0) byte |= 0x80;
      headerBytes.push(byte);
    }
    // The continuation bits belong on the earlier bytes: rebuild properly.
    const header = Buffer.allocUnsafe(headerBytes.length);
    header[0] = first | (headerBytes.length > 1 ? 0x80 : 0);
    for (let i = 1; i < headerBytes.length; i += 1) {
      header[i] = headerBytes[i];
    }
    const compressed = deflateSync(data, { level: 1 });
    parts.push(header, compressed);
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// -------------------------------------------------------------------------------------------
// store
// -------------------------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
}

interface Comment {
  id: number;
  body: string;
}

interface Issue {
  number: number;
  id: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: Comment[];
  jsonCache: Buffer | null;
}

interface Pull {
  number: number;
  id: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
}

interface Repo {
  owner: string;
  name: string;
  description: string;
  privateFlag: boolean;
  defaultBranch: string;
  databaseId: number;
  id: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Issue[];
  pulls: Pull[];
  labels: Map<string, Label>;
  nextIssue: number;
  nextPull: number;
  nextComment: number;
  seq: number;
  packCache: Map<string, Buffer>;
  lsRefsCache: Map<string, Buffer>;
  advCache: Map<string, Buffer>;
}

const repos = new Map<string, Repo>();
let nextDatabaseId = 5000;
let repoSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function lookupRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepo(owner: string, name: string, description: string, privateFlag: boolean): Repo {
  const repo: Repo = {
    owner,
    name,
    description,
    privateFlag,
    defaultBranch: DEFAULT_BRANCH,
    databaseId: nextDatabaseId++,
    id: globalId('R', `${owner}/${name}`),
    refs: new Map(),
    objects: new Map(),
    issues: [],
    pulls: [],
    labels: new Map(),
    nextIssue: 1,
    nextPull: 1,
    nextComment: 1,
    seq: repoSeq++,
    packCache: new Map(),
    lsRefsCache: new Map(),
    advCache: new Map(),
  };
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function putObject(repo: Repo, type: GitType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function refTip(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}

function invalidatePackCache(repo: Repo): void {
  repo.packCache.clear();
  repo.lsRefsCache.clear();
  repo.advCache.clear();
}

// -------------------------------------------------------------------------------------------
// trees and commits
// -------------------------------------------------------------------------------------------

/** Walk a tree to a path; returns the entry or null. */
function treeEntryAt(repo: Repo, treeOid: string, path: string): TreeEntry | null {
  const segments = path.split('/').filter((s) => s !== '');
  let current = treeOid;
  for (let i = 0; i < segments.length; i += 1) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === segments[i]);
    if (!entry) return null;
    if (i === segments.length - 1) return entry;
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}

/** Set (or delete with null) a path in a tree, rebuilding parents; returns the new root tree oid. */
function treeSetPath(repo: Repo, treeOid: string | null, path: string, blobOid: string | null): string {
  const segments = path.split('/').filter((s) => s !== '');
  const build = (oid: string | null, depth: number): string => {
    const entries: TreeEntry[] = oid === null ? [] : parseTree(repo.objects.get(oid)!.data);
    const name = segments[depth];
    if (depth === segments.length - 1) {
      const idx = entries.findIndex((e) => e.name === name);
      if (blobOid === null) {
        if (idx >= 0) entries.splice(idx, 1);
      } else if (idx >= 0) {
        entries[idx] = { mode: '100644', name, oid: blobOid };
      } else {
        entries.push({ mode: '100644', name, oid: blobOid });
      }
    } else {
      const idx = entries.findIndex((e) => e.name === name);
      const childOid = idx >= 0 && entries[idx].mode === '40000' ? entries[idx].oid : null;
      const newChild = build(childOid, depth + 1);
      const childObj = repo.objects.get(newChild)!;
      const childEntries = parseTree(childObj.data);
      if (childEntries.length === 0 && blobOid === null) {
        if (idx >= 0) entries.splice(idx, 1);
      } else if (idx >= 0) {
        entries[idx] = { mode: '40000', name, oid: newChild };
      } else {
        entries.push({ mode: '40000', name, oid: newChild });
      }
    }
    return putObject(repo, 'tree', buildTree(entries));
  };
  return build(treeOid, 0);
}

/** Flatten a tree to path -> entry (files only). */
function treeFlatten(repo: Repo, treeOid: string, prefix: string, out: Map<string, TreeEntry>): void {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') treeFlatten(repo, entry.oid, path, out);
    else out.set(path, entry);
  }
}

function commitTreeOid(repo: Repo, commitOid: string): string {
  return parseCommit(repo.objects.get(commitOid)!.data).tree;
}

/** Create a commit on a branch tip (or unborn) and move the ref. Returns the commit oid. */
function commitOnBranch(repo: Repo, branch: string, message: string, apply: (treeOid: string | null) => string | null): string {
  const ref = `refs/heads/${branch}`;
  const tip = refTip(repo, ref);
  const baseTree = tip === undefined ? null : commitTreeOid(repo, tip);
  const newTree = apply(baseTree);
  if (newTree === null) throw new Error('commit would be empty');
  const parents = tip === undefined ? [] : [tip];
  const commitOid = putObject(repo, 'commit', buildCommit(newTree, parents, message));
  repo.refs.set(ref, commitOid);
  invalidatePackCache(repo);
  return commitOid;
}

/** True when `ancestor` is reachable from `descendant` (or equal). */
function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (parent === ancestor) return true;
      queue.push(parent);
    }
  }
  return false;
}

/** The merge base of two commits: the first common ancestor found walking from `a`. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const bAncestors = new Set<string>();
  const queueB = [b];
  while (queueB.length > 0) {
    const oid = queueB.pop()!;
    if (bAncestors.has(oid)) continue;
    bAncestors.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queueB.push(parent);
  }
  const queueA = [a];
  const seenA = new Set<string>();
  while (queueA.length > 0) {
    const oid = queueA.shift()!;
    if (seenA.has(oid)) continue;
    seenA.add(oid);
    if (bAncestors.has(oid)) return oid;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) queueA.push(parent);
  }
  return null;
}

/** Peel a tag object to its target commit (following nested tags). */
function peelToCommit(repo: Repo, oid: string): string {
  let current = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tag') return current;
    current = parseTag(obj.data).object;
  }
  return current;
}

// -------------------------------------------------------------------------------------------
// fetch computation (upload-pack)
// -------------------------------------------------------------------------------------------

interface FetchPlan {
  send: Set<string>;
  shallowOut: string[];
  unshallowOut: string[];
}

/** Closure of `roots`, but the walk stops at commits in `stopAt` (their parents are not walked). */
function closureStopAt(repo: Repo, roots: Iterable<string>, stopAt: Set<string>): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      queue.push(commit.tree);
      if (!stopAt.has(oid)) for (const parent of commit.parents) queue.push(parent);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

function computeFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  shallowIn: readonly string[],
  depth: number | undefined,
): FetchPlan {
  const stopAt = new Set(shallowIn);
  const haveSet = closureStopAt(repo, haves, stopAt);
  const send = new Set<string>();
  const shallowOut: string[] = [];
  if (depth === undefined) {
    for (const oid of closureStopAt(repo, wants, new Set())) {
      if (!haveSet.has(oid)) send.add(oid);
    }
    return { send, shallowOut, unshallowOut: [] };
  }
  // Depth-limited: commits within `depth` generations of a want (the want itself is generation 1).
  const gen = new Map<string, number>();
  const queue: Array<{ oid: string; g: number }> = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (!obj) continue;
    if (obj.type === 'tag') {
      send.add(want);
      const target = peelToCommit(repo, want);
      if (!gen.has(target)) {
        gen.set(target, 1);
        queue.push({ oid: target, g: 1 });
      }
    } else if (obj.type === 'commit') {
      if (!gen.has(want)) {
        gen.set(want, 1);
        queue.push({ oid: want, g: 1 });
      }
    } else {
      send.add(want);
    }
  }
  const deepest = new Set<string>();
  while (queue.length > 0) {
    const { oid, g } = queue.shift()!;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    send.add(oid);
    const commit = parseCommit(obj.data);
    // The commit's tree and blobs always travel with it.
    const treeClosure = closureStopAt(repo, [commit.tree], new Set());
    for (const t of treeClosure) send.add(t);
    if (g >= depth) {
      deepest.add(oid);
      continue;
    }
    for (const parent of commit.parents) {
      if (!gen.has(parent)) {
        gen.set(parent, g + 1);
        queue.push({ oid: parent, g: g + 1 });
      }
    }
  }
  for (const oid of [...send]) if (haveSet.has(oid)) send.delete(oid);
  for (const oid of deepest) if (send.has(oid)) shallowOut.push(oid);
  // An old shallow boundary is unshallowed when its parent is now included.
  const unshallowOut: string[] = [];
  for (const boundary of shallowIn) {
    const obj = repo.objects.get(boundary);
    if (!obj || obj.type !== 'commit') continue;
    const commit = parseCommit(obj.data);
    if (commit.parents.length > 0 && commit.parents.every((p) => send.has(p) || haveSet.has(p)) && send.has(boundary)) {
      unshallowOut.push(boundary);
    }
  }
  return { send, shallowOut, unshallowOut };
}

/** Build a pack for a fetch: objects in a fixed order, no deltas. */
function packForFetch(repo: Repo, send: Set<string>): Buffer {
  const list: GitObject[] = [];
  const oids = [...send].sort();
  for (const oid of oids) {
    const obj = repo.objects.get(oid);
    if (obj) list.push(obj);
  }
  return writePack(list);
}

// -------------------------------------------------------------------------------------------
// HTTP layer
// -------------------------------------------------------------------------------------------

let requestCounter = 0;
let SERVER_PORT = 0;

/** Minimal request/response surface the handlers use, backed by a raw TCP socket. */
interface MiniReq {
  method: string;
  url: string;
  headers: Record<string, string | undefined>;
}

const REASON: Record<number, string> = {
  200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content',
  400: 'Bad Request', 401: 'Unauthorized', 404: 'Not Found', 405: 'Method Not Allowed',
  409: 'Conflict', 413: 'Content Too Large', 422: 'Unprocessable Entity', 500: 'Internal Server Error',
};

class MiniRes {
  writableEnded = false;
  private status = 200;
  private headers: Record<string, string | number> = {};
  private socket: Socket;
  constructor(socket: Socket) {
    this.socket = socket;
  }
  writeHead(status: number, headers: Record<string, string | number>): void {
    this.status = status;
    this.headers = headers;
  }
  end(body?: Buffer): void {
    if (this.writableEnded) return;
    this.writableEnded = true;
    // One write for the whole response: status line + headers + body.
    const b = body ?? EMPTY_BUFFER;
    // v5: no Date header (xuen-zz omits it too; saves a Date format per response).
    let head = `HTTP/1.1 ${this.status} ${REASON[this.status] ?? ''}\r\n`;
    for (const k of Object.keys(this.headers)) head += `${k}: ${this.headers[k]}\r\n`;
    if (this.headers['content-length'] === undefined) head += `content-length: ${b.length}\r\n`;
    head += 'connection: keep-alive\r\n\r\n';
    const headBuf = Buffer.from(head, 'ascii');
    if (b.length === 0) this.socket.write(headBuf);
    else if (b.length > 4096) { this.socket.write(headBuf); this.socket.write(b); }
    else this.socket.write(Buffer.concat([headBuf, b]));
  }
  destroy(): void {
    this.socket.destroy();
  }
}

interface ReqCtx {
  req: MiniReq;
  res: MiniRes;
  method: string;
  pathname: string;
  queryString: string;
  queryCache: URLSearchParams | null;
  segments: string[];
  body: Buffer;
  json: Json | null;
  jsonError: boolean;
}

/** Parse one complete HTTP/1.1 request off the front of `buf`, or null when more bytes are needed. */
function tryParseRequest(buf: Buffer): { method: string; url: string; headers: Record<string, string | undefined>; body: Buffer; keepAlive: boolean; consumed: number } | null {
  const headEnd = buf.indexOf('\r\n\r\n');
  if (headEnd < 0) return null;
  const head = buf.subarray(0, headEnd).toString('ascii');
  const lines = head.split('\r\n');
  const first = lines[0] ?? '';
  const sp1 = first.indexOf(' ');
  const sp2 = first.indexOf(' ', sp1 + 1);
  if (sp1 < 0 || sp2 < 0) return null;
  const method = first.slice(0, sp1);
  const url = first.slice(sp1 + 1, sp2);
  const version = first.slice(sp2 + 1);
  const headers: Record<string, string | undefined> = {};
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i]!;
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  const conn = (headers['connection'] ?? '').toLowerCase();
  const keepAlive = conn === 'close' ? false : conn === 'keep-alive' ? true : version !== 'HTTP/1.0';
  const bodyStart = headEnd + 4;
  const te = headers['transfer-encoding'];
  if (te !== undefined && te.toLowerCase().includes('chunked')) {
    let off = bodyStart;
    const chunks: Buffer[] = [];
    for (;;) {
      const eol = buf.indexOf('\r\n', off);
      if (eol < 0) return null;
      const size = Number.parseInt(buf.subarray(off, eol).toString('ascii').trim(), 16);
      if (!Number.isFinite(size) || size < 0) return null;
      off = eol + 2;
      if (size === 0) {
        const endEol = buf.indexOf('\r\n', off);
        if (endEol < 0) return null;
        off = endEol + 2;
        return { method, url, headers, body: chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks), keepAlive, consumed: off };
      }
      if (off + size + 2 > buf.length) return null;
      chunks.push(buf.subarray(off, off + size));
      off += size + 2;
    }
  }
  const len = Number(headers['content-length'] ?? '0');
  if (!Number.isFinite(len) || len < 0) return null;
  if (bodyStart + len > buf.length) return null;
  return { method, url, headers, body: len === 0 ? EMPTY_BUFFER : buf.subarray(bodyStart, bodyStart + len), keepAlive, consumed: bodyStart + len };
}

/** Lazily parse the query string (most hot paths never touch it). */
function queryGet(ctx: ReqCtx, name: string): string | null {
  if (ctx.queryCache === null) ctx.queryCache = new URLSearchParams(ctx.queryString);
  return ctx.queryCache.get(name);
}

function sendBuffer(ctx: ReqCtx, status: number, body: Buffer, contentType: string, extra?: Record<string, string>): void {
  const res = ctx.res;
  const headers: Record<string, string | number> = {
    'content-type': contentType,
    'x-github-request-id': `req-${++requestCounter}`,
    'content-length': body.length,
  };
  // Avoid the spread (and the `?? {}` empty object) on the common no-extra path.
  if (extra !== undefined) Object.assign(headers, extra);
  res.writeHead(status, headers);
  res.end(body);
}

function sendJson(ctx: ReqCtx, status: number, value: unknown, extra?: Record<string, string>): void {
  sendBuffer(ctx, status, Buffer.from(JSON.stringify(value), 'utf8'), 'application/json; charset=utf-8', extra);
}

function sendError(ctx: ReqCtx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}

const BEARER_TOKEN = TOKEN === '' ? '' : `Bearer ${TOKEN}`;

function authorized(ctx: ReqCtx): boolean {
  if (TOKEN === '') return true;
  const header = ctx.req.headers.authorization;
  return header === BEARER_TOKEN;
}

function decodeSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parsePath(pathname: string): string[] {
  const raw = pathname.split('/').filter((s) => s !== '');
  // Most paths have no %-escapes; decodeURIComponent costs ~0.2µs per segment.
  if (pathname.indexOf('%') < 0) return raw;
  return raw.map(decodeSegment);
}

// -------------------------------------------------------------------------------------------
// REST shapes
// -------------------------------------------------------------------------------------------

function repoJson(repo: Repo): Json {
  return {
    id: repo.id,
    databaseId: repo.databaseId,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0 },
    private: repo.privateFlag,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    created_at: TRIAL_NOW,
    updated_at: TRIAL_NOW,
  };
}

function issueJson(issue: Issue, repo: Repo): Json {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    created_at: TRIAL_NOW,
    updated_at: TRIAL_NOW,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}

function issueJsonCached(issue: Issue, repo: Repo): Buffer {
  if (issue.jsonCache === null) {
    issue.jsonCache = Buffer.from(JSON.stringify(issueJson(issue, repo)), 'utf8');
  }
  return issue.jsonCache;
}

function pullJson(pull: Pull, repo: Repo): Json {
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head, sha: pull.headSha, label: `${repo.owner}:${pull.head}` },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repo.owner}:${pull.base}` },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    created_at: TRIAL_NOW,
    updated_at: TRIAL_NOW,
  };
}

/** Resolve a repo from the path, enforcing viewer ownership (foreign owner -> 404). */
function resolveRepo(ctx: ReqCtx, owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return lookupRepo(owner, name) ?? null;
}

function refShaOf(repo: Repo, branch: string): string | undefined {
  return refTip(repo, `refs/heads/${branch}`);
}

// -------------------------------------------------------------------------------------------
// REST: repositories, branches, commits, contents
// -------------------------------------------------------------------------------------------

function handleUserRepos(ctx: ReqCtx): void {
  if (ctx.method === 'POST') {
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const name = typeof ctx.json.name === 'string' ? ctx.json.name : '';
    if (name === '') {
      sendError(ctx, 422, 'name is required');
      return;
    }
    if (lookupRepo(VIEWER_LOGIN, name)) {
      sendError(ctx, 422, `Repository ${name} already exists`);
      return;
    }
    const description = typeof ctx.json.description === 'string' ? ctx.json.description : '';
    const privateFlag = ctx.json.private === true;
    const repo = createRepo(VIEWER_LOGIN, name, description, privateFlag);
    sendJson(ctx, 201, repoJson(repo));
    return;
  }
  if (ctx.method === 'GET') {
    const perPage = Math.max(1, Math.min(100, Number(queryGet(ctx, 'per_page') ?? '30') || 30));
    const page = Math.max(1, Number(queryGet(ctx, 'page') ?? '1') || 1);
    const mine = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.seq - b.seq);
    const start = (page - 1) * perPage;
    const slice = mine.slice(start, start + perPage);
    const extra: Record<string, string> = {};
    if (start + perPage < mine.length) {
      const host = ctx.req.headers.host ?? `127.0.0.1:${SERVER_PORT}`;
      const nextUrl = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
      extra.link = `<${nextUrl}>; rel="next"`;
    }
    sendJson(ctx, 200, slice.map(repoJson), extra);
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

function handleRepoRoot(ctx: ReqCtx, owner: string, name: string): void {
  const repo = resolveRepo(ctx, owner, name);
  if (ctx.method === 'GET') {
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    sendJson(ctx, 200, repoJson(repo));
    return;
  }
  if (ctx.method === 'PATCH') {
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    if (typeof ctx.json.description === 'string') repo.description = ctx.json.description;
    sendJson(ctx, 200, repoJson(repo));
    return;
  }
  if (ctx.method === 'DELETE') {
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    repos.delete(repoKey(owner, name));
    ctx.res.writeHead(204, { 'x-github-request-id': `req-${++requestCounter}` });
    ctx.res.end();
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

function handleBranches(ctx: ReqCtx, repo: Repo): void {
  if (ctx.method !== 'GET') {
    sendError(ctx, 405, 'Method Not Allowed');
    return;
  }
  const out: Json[] = [];
  const names = new Set<string>([repo.defaultBranch]);
  for (const ref of repo.refs.keys()) {
    if (ref.startsWith('refs/heads/')) names.add(ref.slice('refs/heads/'.length));
  }
  for (const name of [...names].sort()) {
    const sha = refShaOf(repo, name);
    if (sha !== undefined) out.push({ name, commit: { sha } });
  }
  sendJson(ctx, 200, out);
}

function handleBranch(ctx: ReqCtx, repo: Repo, branch: string): void {
  if (ctx.method !== 'GET') {
    sendError(ctx, 405, 'Method Not Allowed');
    return;
  }
  const sha = refShaOf(repo, branch);
  if (sha === undefined) {
    sendError(ctx, 404, 'Branch not found');
    return;
  }
  sendJson(ctx, 200, { name: branch, commit: { sha } });
}

function handleCommits(ctx: ReqCtx, repo: Repo): void {
  if (ctx.method !== 'GET') {
    sendError(ctx, 405, 'Method Not Allowed');
    return;
  }
  const ref = queryGet(ctx, 'sha') ?? repo.defaultBranch;
  const tip = refShaOf(repo, ref) ?? (isOid(ref) ? ref : undefined);
  if (tip === undefined || !repo.objects.has(tip)) {
    sendJson(ctx, 200, []);
    return;
  }
  const out: Json[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const commit = parseCommit(obj.data);
    out.push({
      sha: oid,
      commit: {
        message: commit.message.replace(/\n+$/, ''),
        author: { name: VIEWER_NAME, email: VIEWER_EMAIL },
        committer: { name: VIEWER_NAME, email: VIEWER_EMAIL },
      },
    });
    for (const parent of commit.parents) queue.push(parent);
  }
  sendJson(ctx, 200, out);
}

function handleGitRefs(ctx: ReqCtx, repo: Repo, rest: string[]): void {
  // POST /git/refs -> create a branch; GET /git/refs/heads/<branch> -> one ref.
  if (ctx.method === 'POST' && rest.length === 0) {
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const ref = typeof ctx.json.ref === 'string' ? ctx.json.ref : '';
    const sha = typeof ctx.json.sha === 'string' ? ctx.json.sha : '';
    if (!ref.startsWith('refs/heads/') || !isOid(sha) || !repo.objects.has(sha)) {
      sendError(ctx, 422, 'invalid ref or sha');
      return;
    }
    if (repo.refs.has(ref)) {
      sendError(ctx, 422, 'Reference already exists');
      return;
    }
    repo.refs.set(ref, sha);
    invalidatePackCache(repo);
    sendJson(ctx, 201, { ref, object: { sha } });
    return;
  }
  if (ctx.method === 'GET' && rest.length >= 2 && rest[0] === 'heads') {
    const branch = rest.slice(1).join('/');
    const sha = refShaOf(repo, branch);
    if (sha === undefined) {
      sendError(ctx, 404, 'Reference not found');
      return;
    }
    sendJson(ctx, 200, { ref: `refs/heads/${branch}`, object: { sha } });
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

function handleContents(ctx: ReqCtx, repo: Repo, pathParts: string[]): void {
  const path = pathParts.join('/');
  const refParam = queryGet(ctx, 'ref') ?? undefined;
  const branch = refParam ?? repo.defaultBranch;
  if (ctx.method === 'GET') {
    const tip = refShaOf(repo, branch) ?? (isOid(branch) ? branch : undefined);
    if (tip === undefined || !repo.objects.has(tip)) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    const treeOid = commitTreeOid(repo, tip);
    if (path === '') {
      const out: Json[] = [];
      const obj = repo.objects.get(treeOid);
      if (obj) {
        for (const entry of parseTree(obj.data)) {
          out.push({ type: entry.mode === '40000' ? 'dir' : 'file', name: entry.name, path: entry.name, sha: entry.oid });
        }
      }
      sendJson(ctx, 200, out);
      return;
    }
    const entry = treeEntryAt(repo, treeOid, path);
    if (!entry) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (entry.mode === '40000') {
      const out: Json[] = [];
      const obj = repo.objects.get(entry.oid);
      if (obj) {
        for (const child of parseTree(obj.data)) {
          out.push({ type: child.mode === '40000' ? 'dir' : 'file', name: child.name, path: `${path}/${child.name}`, sha: child.oid });
        }
      }
      sendJson(ctx, 200, out);
      return;
    }
    const blob = repo.objects.get(entry.oid);
    if (!blob) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    sendJson(ctx, 200, {
      type: 'file',
      encoding: 'base64',
      content: blob.data.toString('base64'),
      sha: entry.oid,
      size: blob.data.length,
      name: path.split('/').pop() ?? path,
      path,
    });
    return;
  }
  if (ctx.method === 'PUT') {
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const message = typeof ctx.json.message === 'string' ? ctx.json.message : 'update';
    const contentB64 = typeof ctx.json.content === 'string' ? ctx.json.content : '';
    const branchParam = typeof ctx.json.branch === 'string' ? ctx.json.branch : branch;
    const shaParam = typeof ctx.json.sha === 'string' ? ctx.json.sha : undefined;
    const content = b64decode(contentB64);
    const tip = refShaOf(repo, branchParam);
    const baseTree = tip === undefined ? null : commitTreeOid(repo, tip);
    const existing = baseTree === null ? null : treeEntryAt(repo, baseTree, path);
    if (shaParam !== undefined) {
      if (!existing || existing.oid !== shaParam) {
        sendError(ctx, 409, 'sha does not match the current file');
        return;
      }
    }
    const blobOid = putObject(repo, 'blob', content);
    const isUpdate = existing !== null;
    const commitOid = commitOnBranch(repo, branchParam, message, (tree) => treeSetPath(repo, tree, path, blobOid));
    sendJson(ctx, isUpdate ? 200 : 201, {
      content: { sha: blobOid, encoding: 'base64', size: content.length, name: path.split('/').pop() ?? path, path },
      commit: { sha: commitOid },
    });
    return;
  }
  if (ctx.method === 'DELETE') {
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const message = typeof ctx.json.message === 'string' ? ctx.json.message : 'delete';
    const shaParam = typeof ctx.json.sha === 'string' ? ctx.json.sha : undefined;
    const tip = refShaOf(repo, branch);
    if (tip === undefined) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    const baseTree = commitTreeOid(repo, tip);
    const existing = treeEntryAt(repo, baseTree, path);
    if (!existing) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (shaParam !== undefined && existing.oid !== shaParam) {
      sendError(ctx, 409, 'sha does not match the current file');
      return;
    }
    const commitOid = commitOnBranch(repo, branch, message, (tree) => treeSetPath(repo, tree, path, null));
    sendJson(ctx, 200, { commit: { sha: commitOid } });
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

// -------------------------------------------------------------------------------------------
// REST: labels, issues, pull requests
// -------------------------------------------------------------------------------------------

function handleLabels(ctx: ReqCtx, repo: Repo): void {
  if (ctx.method !== 'POST') {
    sendError(ctx, 405, 'Method Not Allowed');
    return;
  }
  if (ctx.jsonError || ctx.json === null) {
    sendError(ctx, 400, 'malformed JSON body');
    return;
  }
  const name = typeof ctx.json.name === 'string' ? ctx.json.name : '';
  const color = typeof ctx.json.color === 'string' ? ctx.json.color : '000000';
  if (name === '') {
    sendError(ctx, 422, 'name is required');
    return;
  }
  const label: Label = { name, color };
  repo.labels.set(name, label);
  sendJson(ctx, 201, label);
}

function handleIssues(ctx: ReqCtx, repo: Repo): void {
  if (ctx.method === 'POST') {
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const title = typeof ctx.json.title === 'string' ? ctx.json.title : '';
    const body = typeof ctx.json.body === 'string' ? ctx.json.body : '';
    const labelNames = Array.isArray(ctx.json.labels) ? (ctx.json.labels as unknown[]) : [];
    const labels: Label[] = [];
    for (const labelName of labelNames) {
      if (typeof labelName !== 'string') continue;
      const label = repo.labels.get(labelName);
      if (!label) {
        sendError(ctx, 422, `label ${labelName} does not exist`);
        return;
      }
      labels.push(label);
    }
    const number = repo.nextIssue++;
    const issue: Issue = {
      number,
      id: globalId('I', `${repo.owner}/${repo.name}#${number}`),
      title,
      body,
      state: 'open',
      labels,
      comments: [],
      jsonCache: null,
    };
    repo.issues.push(issue);
    sendJson(ctx, 201, issueJson(issue, repo));
    return;
  }
  if (ctx.method === 'GET') {
    const state = queryGet(ctx, 'state') ?? 'open';
    const sort = queryGet(ctx, 'sort') ?? 'created';
    const direction = queryGet(ctx, 'direction') ?? 'desc';
    const perPage = Math.max(1, Math.min(100, Number(queryGet(ctx, 'per_page') ?? '30') || 30));
    const page = Math.max(1, Number(queryGet(ctx, 'page') ?? '1') || 1);
    let list = repo.issues;
    if (state !== 'all') list = list.filter((i) => i.state === state);
    if (sort === 'created') {
      list = [...list].sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
    }
    const start = (page - 1) * perPage;
    const slice = list.slice(start, start + perPage);
    sendJson(ctx, 200, slice.map((issue) => issueJson(issue, repo)));
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

function findIssue(repo: Repo, number: number): Issue | undefined {
  return repo.issues.find((i) => i.number === number);
}

function handleIssueOne(ctx: ReqCtx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (ctx.method === 'GET') {
    if (!issue) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    sendBuffer(ctx, 200, issueJsonCached(issue, repo), 'application/json; charset=utf-8');
    return;
  }
  if (ctx.method === 'PATCH') {
    if (!issue) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    if (typeof ctx.json.title === 'string') issue.title = ctx.json.title;
    if (typeof ctx.json.body === 'string') issue.body = ctx.json.body;
    if (ctx.json.state === 'open' || ctx.json.state === 'closed') issue.state = ctx.json.state;
    issue.jsonCache = null;
    sendJson(ctx, 200, issueJson(issue, repo));
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

function handleIssueComments(ctx: ReqCtx, repo: Repo, number: number): void {
  const issue = findIssue(repo, number);
  if (ctx.method === 'POST') {
    if (!issue) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const body = typeof ctx.json.body === 'string' ? ctx.json.body : '';
    const comment: Comment = { id: repo.nextComment++, body };
    issue.comments.push(comment);
    sendJson(ctx, 201, { id: comment.id, body: comment.body });
    return;
  }
  if (ctx.method === 'GET') {
    if (!issue) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    sendJson(ctx, 200, issue.comments.map((c) => ({ id: c.id, body: c.body })));
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

function computeDiff(repo: Repo, baseOid: string, headOid: string): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const baseTree = commitTreeOid(repo, baseOid);
  const headTree = commitTreeOid(repo, headOid);
  const baseMap = new Map<string, TreeEntry>();
  const headMap = new Map<string, TreeEntry>();
  treeFlatten(repo, baseTree, '', baseMap);
  treeFlatten(repo, headTree, '', headMap);
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const countLines = (oid: string): number => {
    const obj = repo.objects.get(oid);
    if (!obj) return 0;
    const text = obj.data.toString('utf8');
    if (text === '') return 0;
    return text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
  };
  for (const [path, headEntry] of headMap) {
    const baseEntry = baseMap.get(path);
    if (!baseEntry) {
      const additions = countLines(headEntry.oid);
      out.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (baseEntry.oid !== headEntry.oid) {
      const additions = countLines(headEntry.oid);
      const deletions = countLines(baseEntry.oid);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  for (const [path] of baseMap) {
    if (!headMap.has(path)) {
      const deletions = countLines(baseMap.get(path)!.oid);
      out.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    }
  }
  return out.sort((a, b) => (a.filename < b.filename ? -1 : 1));
}

function handlePulls(ctx: ReqCtx, repo: Repo): void {
  if (ctx.method === 'POST') {
    if (ctx.jsonError || ctx.json === null) {
      sendError(ctx, 400, 'malformed JSON body');
      return;
    }
    const head = typeof ctx.json.head === 'string' ? ctx.json.head : '';
    const base = typeof ctx.json.base === 'string' ? ctx.json.base : repo.defaultBranch;
    const title = typeof ctx.json.title === 'string' ? ctx.json.title : '';
    const body = typeof ctx.json.body === 'string' ? ctx.json.body : '';
    const headSha = refShaOf(repo, head);
    const baseSha = refShaOf(repo, base);
    if (headSha === undefined || baseSha === undefined) {
      sendError(ctx, 422, 'head or base branch not found');
      return;
    }
    const number = repo.nextPull++;
    const pull: Pull = {
      number,
      id: globalId('PR', `${repo.owner}/${repo.name}#${number}`),
      title,
      body,
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      head,
      base,
      headSha,
      baseSha,
    };
    repo.pulls.push(pull);
    sendJson(ctx, 201, pullJson(pull, repo));
    return;
  }
  if (ctx.method === 'GET') {
    const state = queryGet(ctx, 'state') ?? 'open';
    let list = repo.pulls;
    if (state !== 'all') list = list.filter((p) => p.state === state);
    sendJson(ctx, 200, list.map((pull) => pullJson(pull, repo)));
    return;
  }
  sendError(ctx, 405, 'Method Not Allowed');
}

function findPull(repo: Repo, number: number): Pull | undefined {
  return repo.pulls.find((p) => p.number === number);
}

function prMergeable(repo: Repo, pull: Pull): boolean {
  if (pull.state !== 'open') return false;
  const baseSha = refShaOf(repo, pull.base) ?? pull.baseSha;
  const base = mergeBase(repo, pull.headSha, baseSha);
  if (base === null) return true;
  const headMap = new Map<string, TreeEntry>();
  const baseMap = new Map<string, TreeEntry>();
  const mbMap = new Map<string, TreeEntry>();
  treeFlatten(repo, commitTreeOid(repo, pull.headSha), '', headMap);
  treeFlatten(repo, commitTreeOid(repo, baseSha), '', baseMap);
  treeFlatten(repo, commitTreeOid(repo, base), '', mbMap);
  for (const [path, headEntry] of headMap) {
    const mbEntry = mbMap.get(path);
    const baseEntry = baseMap.get(path);
    const headChanged = mbEntry === undefined ? true : mbEntry.oid !== headEntry.oid;
    const baseChanged = mbEntry === undefined
      ? baseEntry !== undefined
      : baseEntry === undefined || mbEntry.oid !== baseEntry.oid;
    if (headChanged && baseChanged) return false;
  }
  return true;
}

function mergePull(repo: Repo, pull: Pull): { sha: string } | null {
  if (!prMergeable(repo, pull)) return null;
  const baseSha = refShaOf(repo, pull.base) ?? pull.baseSha;
  const base = mergeBase(repo, pull.headSha, baseSha);
  const headMap = new Map<string, TreeEntry>();
  const baseMap = new Map<string, TreeEntry>();
  treeFlatten(repo, commitTreeOid(repo, pull.headSha), '', headMap);
  treeFlatten(repo, commitTreeOid(repo, baseSha), '', baseMap);
  // Squash merge: base tree + every file the head changed since the merge base.
  const mbMap = new Map<string, TreeEntry>();
  if (base !== null) treeFlatten(repo, commitTreeOid(repo, base), '', mbMap);
  let newTree = commitTreeOid(repo, baseSha);
  for (const [path, headEntry] of headMap) {
    const mbEntry = mbMap.get(path);
    if (!mbEntry || mbEntry.oid !== headEntry.oid) {
      newTree = treeSetPath(repo, newTree, path, headEntry.oid);
    }
  }
  for (const [path] of mbMap) {
    if (!headMap.has(path) && baseMap.has(path)) {
      // deleted on head, unchanged on base -> remove
      const mbEntry = mbMap.get(path)!;
      const baseEntry = baseMap.get(path)!;
      if (mbEntry.oid === baseEntry.oid) newTree = treeSetPath(repo, newTree, path, null);
    }
  }
  const parents = [baseSha];
  const commitOid = putObject(repo, 'commit', buildCommit(newTree, parents, `Merge pull request #${pull.number} from ${pull.head}`));
  repo.refs.set(`refs/heads/${pull.base}`, commitOid);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = TRIAL_NOW;
  pull.mergeCommitSha = commitOid;
  invalidatePackCache(repo);
  return { sha: commitOid };
}

function handlePullOne(ctx: ReqCtx, repo: Repo, number: number, rest: string[]): void {
  const pull = findPull(repo, number);
  if (ctx.method === 'GET' && rest.length === 0) {
    if (!pull) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    sendJson(ctx, 200, pullJson(pull, repo));
    return;
  }
  if (ctx.method === 'GET' && rest.length === 1 && rest[0] === 'files') {
    if (!pull) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    const files = computeDiff(repo, pull.baseSha, pull.headSha);
    sendJson(ctx, 200, files);
    return;
  }
  if (ctx.method === 'PUT' && rest.length === 1 && rest[0] === 'merge') {
    if (!pull) {
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (pull.state !== 'open') {
      sendError(ctx, 405, 'Pull request is already closed');
      return;
    }
    const merged = mergePull(repo, pull);
    if (merged === null) {
      sendError(ctx, 405, 'Merge conflict');
      return;
    }
    sendJson(ctx, 200, { sha: merged.sha, merged: true, message: `Pull Request #${pull.number} merged` });
    return;
  }
  sendError(ctx, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// REST dispatcher
// -------------------------------------------------------------------------------------------

function dispatchRest(ctx: ReqCtx): boolean {
  const seg = ctx.segments;
  if (seg.length === 2 && seg[0] === 'api' && seg[1] === 'v3') {
    if (ctx.method !== 'GET') {
      sendError(ctx, 405, 'Method Not Allowed');
      return true;
    }
    sendJson(ctx, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (seg.length === 3 && seg[0] === 'api' && seg[1] === 'v3' && seg[2] === 'meta') {
    if (ctx.method !== 'GET') {
      sendError(ctx, 405, 'Method Not Allowed');
      return true;
    }
    sendJson(ctx, 200, { installed_version: SERVER_VERSION });
    return true;
  }
  if (seg.length === 3 && seg[0] === 'api' && seg[1] === 'v3' && seg[2] === 'user') {
    if (ctx.method !== 'GET') {
      sendError(ctx, 405, 'Method Not Allowed');
      return true;
    }
    sendJson(ctx, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL });
    return true;
  }
  if (seg.length === 4 && seg[0] === 'api' && seg[1] === 'v3' && seg[2] === 'user' && seg[3] === 'repos') {
    handleUserRepos(ctx);
    return true;
  }
  if (seg.length >= 4 && seg[0] === 'api' && seg[1] === 'v3' && seg[2] === 'repos') {
    const owner = seg[3];
    const name = seg[4];
    if (name === undefined) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    const repo = resolveRepo(ctx, owner, name);
    const rest = seg.slice(5);
    if (rest.length === 0) {
      handleRepoRoot(ctx, owner, name);
      return true;
    }
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (rest[0] === 'branches' && rest.length === 1) {
      handleBranches(ctx, repo);
      return true;
    }
    if (rest[0] === 'branches' && rest.length >= 2) {
      handleBranch(ctx, repo, rest.slice(1).join('/'));
      return true;
    }
    if (rest[0] === 'commits' && rest.length === 1) {
      handleCommits(ctx, repo);
      return true;
    }
    if (rest[0] === 'git' && rest[1] === 'refs') {
      handleGitRefs(ctx, repo, rest.slice(2));
      return true;
    }
    if (rest[0] === 'contents') {
      handleContents(ctx, repo, rest.slice(1));
      return true;
    }
    if (rest[0] === 'labels' && rest.length === 1) {
      handleLabels(ctx, repo);
      return true;
    }
    if (rest[0] === 'issues' && rest.length === 1) {
      handleIssues(ctx, repo);
      return true;
    }
    if (rest[0] === 'issues' && rest.length >= 2) {
      const n = Number(rest[1]);
      if (!Number.isInteger(n)) {
        sendError(ctx, 404, 'Not Found');
        return true;
      }
      if (rest.length === 2) {
        handleIssueOne(ctx, repo, n);
        return true;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        handleIssueComments(ctx, repo, n);
        return true;
      }
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (rest[0] === 'pulls' && rest.length === 1) {
      handlePulls(ctx, repo);
      return true;
    }
    if (rest[0] === 'pulls' && rest.length >= 2) {
      const n = Number(rest[1]);
      if (!Number.isInteger(n)) {
        sendError(ctx, 404, 'Not Found');
        return true;
      }
      handlePullOne(ctx, repo, n, rest.slice(2));
      return true;
    }
    sendError(ctx, 404, 'Not Found');
    return true;
  }
  return false;
}

// -------------------------------------------------------------------------------------------
// git smart HTTP
// -------------------------------------------------------------------------------------------

function gitRefLines(repo: Repo): string[] {
  const lines: string[] = [];
  const headTip = refShaOf(repo, repo.defaultBranch);
  const headOid = headTip ?? ZERO_OID;
  lines.push(`${headOid} HEAD`);
  for (const [ref, oid] of [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    lines.push(`${oid} ${ref}`);
  }
  return lines;
}

function advertisementV0(repo: Repo, service: string): Buffer {
  const serviceLine = pktLine(`# service=${service}\n`);
  const lines = gitRefLines(repo);
  const parts: Buffer[] = [serviceLine, pktFlush()];
  if (lines.length === 0) return Buffer.concat([...parts, pktFlush()]);
  const caps = service === 'git-upload-pack'
    ? 'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done filter object-format=sha1 agent=forge'
    : 'report-status side-band-64k delete-refs ofs-delta agent=forge';
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (i === 0) {
      const suffix = lines.length === 1 && repo.refs.size === 0 ? ` capabilities^{}\0${caps}` : `\0${caps}`;
      parts.push(pktLine(`${line}${suffix}\n`));
    } else {
      parts.push(pktLine(`${line}\n`));
    }
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function handleInfoRefs(ctx: ReqCtx, repo: Repo, service: string): void {
  const isV2 = ctx.req.headers['git-protocol'] === 'version=2';
  if (service === 'git-upload-pack') {
    if (isV2) {
      sendBuffer(ctx, 200, V2_ADVERTISEMENT, 'application/x-git-upload-pack-advertisement');
      return;
    }
    // The v0 advertisement only depends on the refs: cache it per repo, cleared on any ref change.
    const cached = repo.advCache.get(service);
    if (cached !== undefined) {
      sendBuffer(ctx, 200, cached, 'application/x-git-upload-pack-advertisement');
      return;
    }
    const adv = advertisementV0(repo, 'git-upload-pack');
    repo.advCache.set(service, adv);
    sendBuffer(ctx, 200, adv, 'application/x-git-upload-pack-advertisement');
    return;
  }
  // receive-pack only has a v0 advertisement
  const cached = repo.advCache.get(service);
  if (cached !== undefined) {
    sendBuffer(ctx, 200, cached, 'application/x-git-receive-pack-advertisement');
    return;
  }
  const adv = advertisementV0(repo, 'git-receive-pack');
  repo.advCache.set(service, adv);
  sendBuffer(ctx, 200, adv, 'application/x-git-receive-pack-advertisement');
}

interface LsRefsArgs {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefix: string | null;
}

function handleUploadPackV2(ctx: ReqCtx, repo: Repo): void {
  const decoded = decodePktLines(ctx.body);
  const packets = decoded.packets;
  if (packets.length === 0) {
    sendError(ctx, 400, 'empty upload-pack request');
    return;
  }
  const first = packets[0].payload.toString('utf8').trim();
  if (first === 'command=ls-refs') {
    // The whole request body determines the answer, so its hash is the cache key:
    // a hit skips the packet parse entirely (the clone workload repeats it 50x).
    const bkey = sha1hex(ctx.body);
    const cached = repo.lsRefsCache.get(bkey);
    if (cached !== undefined) {
      sendBuffer(ctx, 200, cached, 'application/x-git-upload-pack-result');
      return;
    }
    // v2 args arrive in the section after the delim packet; agent=/object-format= lines
    // arrive before it. Both sections are data packets, so read them all.
    const args: LsRefsArgs = { peel: false, symrefs: false, unborn: false, prefix: null };
    for (const packet of packets.slice(1)) {
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8').trim();
      if (text === 'peel') args.peel = true;
      else if (text === 'symrefs') args.symrefs = true;
      else if (text === 'unborn') args.unborn = true;
      else if (text.startsWith('ref-prefix ')) args.prefix = text.slice('ref-prefix '.length);
    }
    const out: Buffer[] = [];
    const headTip = refShaOf(repo, repo.defaultBranch);
    const headName = `refs/heads/${repo.defaultBranch}`;
    // HEAD only travels when no prefix filters it out (a prefix only matches ref names).
    const wantHead = args.prefix === null || 'HEAD'.startsWith(args.prefix);
    if (wantHead) {
      if (headTip === undefined) {
        if (args.unborn) out.push(pktLine(`unborn HEAD symref-target:${headName}\n`));
      } else {
        let line = `${headTip} HEAD`;
        if (args.symrefs) line += ` symref-target:${headName}`;
        out.push(pktLine(`${line}\n`));
      }
    }
    const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    for (const [ref, oid] of refs) {
      if (args.prefix !== null && !ref.startsWith(args.prefix)) continue;
      let line = `${oid} ${ref}`;
      if (args.symrefs && ref === headName) line += ` symref-target:${headName}`;
      if (args.peel) {
        const obj = repo.objects.get(oid);
        if (obj && obj.type === 'tag') {
          const target = peelToCommit(repo, oid);
          line += ` peeled:${target}`;
        }
      }
      out.push(pktLine(`${line}\n`));
    }
    out.push(pktFlush());
    const response = Buffer.concat(out);
    repo.lsRefsCache.set(bkey, response);
    sendBuffer(ctx, 200, response, 'application/x-git-upload-pack-result');
    return;
  }
  if (first === 'command=fetch') {
    // The whole request body determines the answer, so its hash is the cache key:
    // a hit skips the packet parse and the fetch plan entirely (the clone workload
    // issues 50 identical fetches).
    const bkey = sha1hex(ctx.body);
    const cached = repo.packCache.get(bkey);
    if (cached !== undefined) {
      sendBuffer(ctx, 200, cached, 'application/x-git-upload-pack-result');
      return;
    }
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowIn: string[] = [];
    let depth: number | undefined;
    let thinPack = false;
    for (const packet of packets.slice(1)) {
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8').trim();
      if (text.startsWith('want ')) wants.push(text.slice(5).trim());
      else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
      else if (text.startsWith('shallow ')) shallowIn.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) depth = Number(text.slice(7).trim());
      else if (text === 'thin-pack') thinPack = true;
    }
    void thinPack;
    const plan = computeFetch(repo, wants, haves, shallowIn, depth);
    const pack = packForFetch(repo, plan.send);
    const knownHaves = haves.filter((h) => repo.objects.has(h));
    const out: Buffer[] = [];
    const ackLines: string[] = [];
    if (haves.length === 0 || knownHaves.length === haves.length) {
      ackLines.push('ready');
    } else {
      ackLines.push('NAK');
    }
    out.push(pktLine('acknowledgments\n'));
    for (const line of ackLines) out.push(pktLine(`${line}\n`));
    out.push(pktDelim());
    if (plan.shallowOut.length > 0 || plan.unshallowOut.length > 0) {
      out.push(pktLine('shallow-info\n'));
      for (const oid of plan.shallowOut) out.push(pktLine(`shallow ${oid}\n`));
      for (const oid of plan.unshallowOut) out.push(pktLine(`unshallow ${oid}\n`));
      out.push(pktDelim());
    }
    out.push(pktLine('packfile\n'));
    // Pack bytes in sideband band 1, chunked so each pkt-line stays under the 65520 limit.
    const CHUNK = 65515;
    for (let off = 0; off < pack.length; off += CHUNK) {
      const slice = pack.subarray(off, off + CHUNK);
      const framed = Buffer.concat([Buffer.from([1]), slice]);
      out.push(pktLine(framed));
    }
    out.push(pktFlush());
    const response = Buffer.concat(out);
    repo.packCache.set(bkey, response);
    sendBuffer(ctx, 200, response, 'application/x-git-upload-pack-result');
    return;
  }
  sendError(ctx, 400, `unknown upload-pack command ${first}`);
}

function handleReceivePack(ctx: ReqCtx, repo: Repo): void {
  const decoded = decodePktLines(ctx.body);
  const packets = decoded.packets;
  // A non-empty body that is not pkt-lines at all is malformed.
  if (ctx.body.length > 0 && packets.length === 0) {
    sendError(ctx, 400, 'malformed receive-pack request');
    return;
  }
  const report: string[] = ['unpack ok'];
  const updates: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let parseOk = true;
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8');
    const nul = text.indexOf('\0');
    const command = nul >= 0 ? text.slice(0, nul) : text;
    const fields = command.trim().split(/\s+/);
    if (fields.length < 3) {
      parseOk = false;
      break;
    }
    const [oldOid, newOid, ref] = fields;
    if (!isOid(oldOid) || !isOid(newOid)) {
      parseOk = false;
      break;
    }
    updates.push({ oldOid, newOid, ref });
  }
  if (!parseOk) {
    sendError(ctx, 400, 'malformed receive-pack request');
    return;
  }
    // The pack bytes follow the flush after the commands; they start with the PACK magic.
  const packIdx = ctx.body.indexOf(PACK_MAGIC);
  const packBytes = packIdx >= 0 ? ctx.body.subarray(packIdx) : Buffer.alloc(0);
  if (updates.length > 0 && packBytes.length > 0) {
    try {
      const { objects } = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) repo.objects.set(oid, obj);
    } catch {
      // A bad pack still gets a report; refs are not applied.
      sendBuffer(ctx, 200, reportBuffer(['unpack failed']), 'application/x-git-receive-pack-result');
      return;
    }
  }
  for (const update of updates) {
    const current = repo.refs.get(update.ref);
    if (update.newOid === ZERO_OID) {
      // Delete.
      if (current === undefined || current !== update.oldOid) {
        report.push(`ng ${update.ref} delete failed`);
      } else {
        repo.refs.delete(update.ref);
        report.push(`ok ${update.ref}`);
      }
      continue;
    }
    if (update.oldOid === ZERO_OID) {
      // Create.
      if (current !== undefined) {
        report.push(`ng ${update.ref} reference already exists`);
        continue;
      }
      if (!repo.objects.has(update.newOid)) {
        report.push(`ng ${update.ref} object not found`);
        continue;
      }
      repo.refs.set(update.ref, update.newOid);
      report.push(`ok ${update.ref}`);
      continue;
    }
    // Update.
    if (current !== update.oldOid) {
      report.push(`ng ${update.ref} old value mismatch`);
      continue;
    }
    if (!isAncestor(repo, update.oldOid, update.newOid)) {
      report.push(`ng ${update.ref} non-fast-forward`);
      continue;
    }
    repo.refs.set(update.ref, update.newOid);
    report.push(`ok ${update.ref}`);
  }
  invalidatePackCache(repo);
  sendBuffer(ctx, 200, reportBuffer(report), 'application/x-git-receive-pack-result');
}

function reportBuffer(lines: string[]): Buffer {
  // One allocation: size the framed report first, then write the pkt-lines straight into it.
  let total = 4; // trailing flush
  for (const line of lines) total += 4 + 1 + Buffer.byteLength(line, 'utf8') + 1;
  const out = Buffer.allocUnsafe(total);
  let off = 0;
  for (const line of lines) {
    const payloadLen = 1 + Buffer.byteLength(line, 'utf8') + 1; // band byte + line + \n
    out.write((payloadLen + 4).toString(16).padStart(4, '0'), off, 4, 'ascii');
    off += 4;
    out[off++] = 1;
    off += out.write(line, off, 'utf8');
    out[off++] = 10; // \n
  }
  out.write('0000', off, 4, 'ascii');
  return out;
}

function dispatchGit(ctx: ReqCtx): boolean {
  const seg = ctx.segments;
  if (seg.length < 2) return false;
  if (!seg[1].endsWith('.git')) return false;
  const owner = seg[0];
  const repoName = seg[1].slice(0, -4);
  const tail = seg.slice(2);
  const repo = resolveRepo(ctx, owner, repoName);
  if (tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs') {
    const service = queryGet(ctx, 'service') ?? '';
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendError(ctx, 400, 'service parameter required');
      return true;
    }
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    handleInfoRefs(ctx, repo, service);
    return true;
  }
  if (tail.length === 1 && tail[0] === 'git-upload-pack') {
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (ctx.method !== 'POST') {
      sendError(ctx, 405, 'Method Not Allowed');
      return true;
    }
    handleUploadPackV2(ctx, repo);
    return true;
  }
  if (tail.length === 1 && tail[0] === 'git-receive-pack') {
    if (!repo) {
      sendError(ctx, 404, 'Not Found');
      return true;
    }
    if (ctx.method !== 'POST') {
      sendError(ctx, 405, 'Method Not Allowed');
      return true;
    }
    handleReceivePack(ctx, repo);
    return true;
  }
  return false;
}

// -------------------------------------------------------------------------------------------
// GraphQL v4
// -------------------------------------------------------------------------------------------

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue } | { __var: string };

interface GqlSelection {
  kind: 'field' | 'fragment';
  name: string;
  alias: string | null;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
  typeCondition: string | null;
}

interface GqlOp {
  operation: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
  varDefaults: Record<string, GqlValue>;
}

function gqlTokenize(input: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < input.length && input[i] !== '\n') i += 1;
      continue;
    }
    if (input.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}():$![]=@'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < input.length && input[j] !== '"') {
        if (input[j] === '\\' && j + 1 < input.length) {
          const esc = input[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += input[j];
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < input.length && /[A-Za-z0-9_]/.test(input[j])) j += 1;
      tokens.push(input.slice(i, j));
      i = j;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < input.length && /[0-9.eE+-]/.test(input[j])) j += 1;
      tokens.push(input.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(input: string) {
    this.tokens = gqlTokenize(input);
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }

  private next(): string | undefined {
    return this.tokens[this.pos++];
  }

  private expect(value: string): void {
    const got = this.next();
    if (got !== value) throw new Error(`expected ${value}, got ${got}`);
  }

  parseOperation(): GqlOp {
    let operation: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    const varDefaults: Record<string, GqlValue> = {};
    const first = this.peek();
    if (first === 'query' || first === 'mutation') {
      operation = this.next() as 'query' | 'mutation';
      const maybeName = this.peek();
      if (maybeName !== undefined && maybeName !== '{' && maybeName !== '(') {
        name = this.next()!;
      }
    }
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== undefined && this.peek() !== ')') {
        if (this.peek() === '$') {
          this.next();
          const varName = this.next()!;
          this.expect(':');
          // skip the type (may include ! or [ ])
          let depth = 0;
          while (this.peek() !== undefined) {
            const tok = this.peek()!;
            if (tok === '=' && depth === 0) break;
            if (tok === ',' && depth === 0) break;
            if (tok === ')' && depth === 0) break;
            if (tok === '[') depth += 1;
            if (tok === ']') depth -= 1;
            this.next();
          }
          if (this.peek() === '=') {
            this.next();
            varDefaults[varName] = this.parseValue();
          }
        } else {
          this.next();
        }
      }
      this.expect(')');
    }
    const selections = this.parseSelectionSet();
    return { operation, name, selections, varDefaults };
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== undefined && this.peek() !== '}') {
      out.push(this.parseSelection());
    }
    this.expect('}');
    return out;
  }

  private parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      let typeCondition: string | null = null;
      if (this.peek() === 'on') {
        this.next();
        typeCondition = this.next()!;
      }
      const selections = this.parseSelectionSet();
      return { kind: 'fragment', name: '', alias: null, args: {}, selections, typeCondition };
    }
    let name = this.next()!;
    let alias: string | null = null;
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next()!;
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== undefined && this.peek() !== ')') {
        const argName = this.next()!;
        this.expect(':');
        args[argName] = this.parseValue();
      }
      this.expect(')');
    }
    // directives (e.g. @include) — skip them
    while (this.peek() === '@') {
      this.next();
      this.next();
      if (this.peek() === '(') {
        let depth = 0;
        while (this.peek() !== undefined) {
          const tok = this.next()!;
          if (tok === '(') depth += 1;
          if (tok === ')') {
            depth -= 1;
            if (depth === 0) break;
          }
        }
      }
    }
    let selections: GqlSelection[] = [];
    if (this.peek() === '{') selections = this.parseSelectionSet();
    return { kind: 'field', name, alias, args, selections, typeCondition: null };
  }

  private parseValue(): GqlValue {
    const tok = this.next()!;
    if (tok === '$') return { __var: this.next()! };
    if (tok === '[') {
      const list: GqlValue[] = [];
      while (this.peek() !== undefined && this.peek() !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (tok === '{') {
      const obj: Record<string, GqlValue> = {};
      while (this.peek() !== undefined && this.peek() !== '}') {
        const key = this.next()!;
        this.expect(':');
        obj[key] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    if (tok.startsWith('"')) return JSON.parse(tok) as string;
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    const num = Number(tok);
    if (!Number.isNaN(num) && /^-?\d/.test(tok)) return num;
    return tok;
  }
}

function resolveVariables(value: GqlValue, variables: Record<string, unknown>, defaults: Record<string, GqlValue>): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    if ('__var' in value) {
      const name = (value as { __var: string }).__var;
      if (variables[name] !== undefined) return variables[name];
      const def = defaults[name];
      return def === undefined ? null : resolveVariables(def, variables, defaults);
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveVariables(v, variables, defaults);
    return out;
  }
  if (Array.isArray(value)) return value.map((v) => resolveVariables(v, variables, defaults));
  return value;
}

function resolveArgs(selection: GqlSelection, variables: Record<string, unknown>, defaults: Record<string, GqlValue>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(selection.args)) out[k] = resolveVariables(v, variables, defaults);
  return out;
}

// Type metadata for introspection and for resolving child types.
const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'author', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'mergedAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  SearchType: [],
};

const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT'],
};

interface GqlContext {
  repo: Repo | null;
  issue: Issue | null;
  pull: Pull | null;
}

function findByGlobalId(id: string): { kind: 'repo' | 'issue' | 'pull'; repo: Repo; issue?: Issue; pull?: Pull } | null {
  for (const repo of repos.values()) {
    if (repo.id === id) return { kind: 'repo', repo };
    const issue = repo.issues.find((i) => i.id === id);
    if (issue) return { kind: 'issue', repo, issue };
    const pull = repo.pulls.find((p) => p.id === id);
    if (pull) return { kind: 'pull', repo, pull };
  }
  return null;
}

function cursorFor(number: number): string {
  return Buffer.from(`cursor:${number}`, 'utf8').toString('base64');
}

function cursorNumber(cursor: string): number | null {
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(decoded);
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

interface ExecState {
  errors: Array<{ message: string }>;
}

function executeSelection(
  parentType: string,
  value: unknown,
  selections: GqlSelection[],
  args: Record<string, unknown>,
  variables: Record<string, unknown>,
  defaults: Record<string, GqlValue>,
  state: ExecState,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (selection.typeCondition !== null && selection.typeCondition !== parentType) continue;
      const inner = executeSelection(parentType, value, selection.selections, args, variables, defaults, state);
      Object.assign(out, inner);
      continue;
    }
    const fieldName = selection.name;
    const outName = selection.alias ?? fieldName;
    const fieldArgs = resolveArgs(selection, variables, defaults);
    const resolved = resolveField(parentType, value, fieldName, fieldArgs, state);
    if (resolved === undefined) {
      // Unknown field: record an error naming it, leave it out of data.
      state.errors.push({ message: `Cannot query field "${fieldName}" on type "${parentType}".` });
      continue;
    }
    const { data: childValue, type: childType } = resolved;
    if (selection.selections.length === 0) {
      out[outName] = childValue;
    } else if (childValue === null || childValue === undefined) {
      out[outName] = null;
    } else if (Array.isArray(childValue)) {
      out[outName] = childValue.map((item) => executeSelection(childType, item, selection.selections, fieldArgs, variables, defaults, state));
    } else {
      out[outName] = executeSelection(childType, childValue, selection.selections, fieldArgs, variables, defaults, state);
    }
  }
  return out;
}

function resolveField(
  parentType: string,
  value: unknown,
  field: string,
  args: Record<string, unknown>,
  state: ExecState,
): { data: unknown; type: string } | undefined {
  void state;
  if (field === '__typename') return { data: parentType, type: 'String' };
  switch (parentType) {
    case 'Query': {
      if (field === 'viewer') return { data: { login: VIEWER_LOGIN, id: VIEWER_ID }, type: 'User' };
      if (field === 'repository') {
        const owner = String(args.owner ?? '');
        const name = String(args.name ?? '');
        const repo = resolveRepo({} as ReqCtx, owner, name);
        return { data: repo ?? null, type: 'Repository' };
      }
      if (field === 'node') {
        const found = findByGlobalId(String(args.id ?? ''));
        if (!found) return { data: null, type: 'Repository' };
        if (found.kind === 'repo') return { data: found.repo, type: 'Repository' };
        if (found.kind === 'issue') return { data: found.issue, type: 'Issue' };
        return { data: found.pull, type: 'PullRequest' };
      }
      if (field === '__type') {
        const name = String(args.name ?? '');
        const fields = GQL_TYPE_FIELDS[name] ?? [];
        const enumValues = GQL_ENUM_VALUES[name] ?? [];
        return {
          data: {
            __gqlType: name,
            name,
            kind: enumValues.length > 0 ? 'ENUM' : 'OBJECT',
            fields: fields.map((f) => ({ name: f })),
            enumValues: enumValues.map((v) => ({ name: v })),
          },
          type: '__Type',
        };
      }
      if (field === '__schema') {
        return { data: { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' } }, type: '__Schema' };
      }
      return undefined;
    }
    case 'Mutation': {
      const input = (args.input ?? {}) as Record<string, unknown>;
      if (field === 'createIssue') {
        const found = findByGlobalId(String(input.repositoryId ?? ''));
        if (!found || found.kind !== 'repo') return { data: null, type: 'CreateIssuePayload' };
        const repo = found.repo;
        const number = repo.nextIssue++;
        const issue: Issue = {
          number,
          id: globalId('I', `${repo.owner}/${repo.name}#${number}`),
          title: String(input.title ?? ''),
          body: typeof input.body === 'string' ? input.body : '',
          state: 'open',
          labels: [],
          comments: [],
          jsonCache: null,
        };
        repo.issues.push(issue);
        return { data: { issue }, type: 'CreateIssuePayload' };
      }
      if (field === 'closeIssue') {
        const found = findByGlobalId(String(input.issueId ?? ''));
        if (!found || found.kind !== 'issue' || !found.issue) return { data: null, type: 'CloseIssuePayload' };
        found.issue.state = 'closed';
        found.issue.jsonCache = null;
        return { data: { issue: found.issue }, type: 'CloseIssuePayload' };
      }
      if (field === 'createPullRequest') {
        const found = findByGlobalId(String(input.repositoryId ?? ''));
        if (!found || found.kind !== 'repo') return { data: null, type: 'CreatePullRequestPayload' };
        const repo = found.repo;
        const head = String(input.headRefName ?? '');
        const base = String(input.baseRefName ?? '');
        const headSha = refShaOf(repo, head);
        const baseSha = refShaOf(repo, base);
        if (headSha === undefined || baseSha === undefined) return { data: null, type: 'CreatePullRequestPayload' };
        const number = repo.nextPull++;
        const pull: Pull = {
          number,
          id: globalId('PR', `${repo.owner}/${repo.name}#${number}`),
          title: String(input.title ?? ''),
          body: typeof input.body === 'string' ? input.body : '',
          state: 'open',
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          head,
          base,
          headSha,
          baseSha,
        };
        repo.pulls.push(pull);
        return { data: { pullRequest: pull }, type: 'CreatePullRequestPayload' };
      }
      if (field === 'mergePullRequest') {
        const found = findByGlobalId(String(input.pullRequestId ?? ''));
        if (!found || found.kind !== 'pull' || !found.pull) return { data: null, type: 'MergePullRequestPayload' };
        const pull = found.pull;
        if (pull.state === 'open') mergePull(found.repo, pull);
        return { data: { pullRequest: pull }, type: 'MergePullRequestPayload' };
      }
      if (field === 'addComment') {
        const found = findByGlobalId(String(input.subjectId ?? ''));
        if (!found || found.kind !== 'issue' || !found.issue) return { data: null, type: 'AddCommentPayload' };
        const issue = found.issue;
        const comment: Comment = { id: found.repo.nextComment++, body: String(input.body ?? '') };
        issue.comments.push(comment);
        return {
          data: { commentEdge: { node: { id: globalId('IC', `${found.repo.owner}/${found.repo.name}#${issue.number}/c${comment.id}`), body: comment.body } } },
          type: 'AddCommentPayload',
        };
      }
      return undefined;
    }
    case 'Repository': {
      const repo = value as Repo;
      if (field === 'id') return { data: repo.id, type: 'ID' };
      if (field === 'databaseId') return { data: repo.databaseId, type: 'Int' };
      if (field === 'name') return { data: repo.name, type: 'String' };
      if (field === 'nameWithOwner') return { data: `${repo.owner}/${repo.name}`, type: 'String' };
      if (field === 'owner') return { data: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0 }, type: 'User' };
      if (field === 'defaultBranchRef') return { data: { name: repo.defaultBranch }, type: 'Ref' };
      if (field === 'viewerPermission') return { data: 'ADMIN', type: 'String' };
      if (field === 'hasIssuesEnabled') return { data: true, type: 'Boolean' };
      if (field === 'issue') {
        const issue = repo.issues.find((i) => i.number === Number(args.number));
        return { data: issue ?? null, type: 'Issue' };
      }
      if (field === 'issues') {
        const first = typeof args.first === 'number' ? args.first : 100;
        const states = Array.isArray(args.states) ? (args.states as string[]) : null;
        const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
        const direction = String(orderBy.direction ?? 'DESC');
        const after = typeof args.after === 'string' ? cursorNumber(args.after) : null;
        let list = [...repo.issues];
        if (states !== null) {
          const want = new Set(states.map((s) => String(s).toLowerCase()));
          list = list.filter((i) => want.has(i.state));
        }
        list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
        if (after !== null) {
          list = direction === 'ASC' ? list.filter((i) => i.number > after) : list.filter((i) => i.number < after);
        }
        const page = list.slice(0, first);
        const hasNextPage = list.length > first;
        const endCursor = page.length > 0 ? cursorFor(page[page.length - 1].number) : null;
        return {
          data: { nodes: page, pageInfo: { hasNextPage, endCursor, hasPreviousPage: false, startCursor: page.length > 0 ? cursorFor(page[0].number) : null }, totalCount: repo.issues.length },
          type: 'IssueConnection',
        };
      }
      if (field === 'pullRequest') {
        const pull = repo.pulls.find((p) => p.number === Number(args.number));
        return { data: pull ?? null, type: 'PullRequest' };
      }
      if (field === 'pullRequests') {
        const first = typeof args.first === 'number' ? args.first : 100;
        const list = [...repo.pulls].sort((a, b) => a.number - b.number).slice(0, first);
        return {
          data: { nodes: list, pageInfo: { hasNextPage: repo.pulls.length > first, endCursor: list.length > 0 ? cursorFor(list[list.length - 1].number) : null, hasPreviousPage: false, startCursor: null }, totalCount: repo.pulls.length },
          type: 'PullRequestConnection',
        };
      }
      return undefined;
    }
    case 'Issue': {
      const issue = value as Issue;
      if (field === 'id') return { data: issue.id, type: 'ID' };
      if (field === 'number') return { data: issue.number, type: 'Int' };
      if (field === 'title') return { data: issue.title, type: 'String' };
      if (field === 'body') return { data: issue.body, type: 'String' };
      if (field === 'state') return { data: issue.state.toUpperCase(), type: 'IssueState' };
      if (field === 'url') return { data: `/api/v3/repos/${VIEWER_LOGIN}/issues/${issue.number}`, type: 'String' };
      if (field === 'createdAt') return { data: TRIAL_NOW, type: 'String' };
      if (field === 'author') return { data: { login: VIEWER_LOGIN, id: VIEWER_ID }, type: 'User' };
      if (field === 'labels') return { data: { nodes: issue.labels }, type: 'LabelConnection' };
      if (field === 'comments') return { data: { nodes: issue.comments }, type: 'IssueCommentConnection' };
      return undefined;
    }
    case 'PullRequest': {
      const pull = value as Pull;
      if (field === 'id') return { data: pull.id, type: 'ID' };
      if (field === 'number') return { data: pull.number, type: 'Int' };
      if (field === 'title') return { data: pull.title, type: 'String' };
      if (field === 'body') return { data: pull.body, type: 'String' };
      if (field === 'headRefName') return { data: pull.head, type: 'String' };
      if (field === 'baseRefName') return { data: pull.base, type: 'String' };
      if (field === 'mergeable') return { data: pull.state === 'open' ? (prMergeable(findRepoOfPull(pull)!, pull) ? 'MERGEABLE' : 'CONFLICTING') : 'UNKNOWN', type: 'String' };
      if (field === 'state') return { data: pull.state.toUpperCase(), type: 'String' };
      if (field === 'merged') return { data: pull.merged, type: 'Boolean' };
      if (field === 'mergedAt') return { data: pull.mergedAt, type: 'String' };
      if (field === 'files') {
        const repo = findRepoOfPull(pull)!;
        const first = typeof args.first === 'number' ? args.first : 100;
        const files = computeDiff(repo, pull.baseSha, pull.headSha).map((f) => ({ path: f.filename }));
        return { data: { nodes: files.slice(0, first), pageInfo: { hasNextPage: files.length > first, endCursor: null, hasPreviousPage: false, startCursor: null }, totalCount: files.length }, type: 'PullRequestFileConnection' };
      }
      return undefined;
    }
    case 'User':
    case 'Actor': {
      const user = value as { login: string; id: number };
      if (field === 'login') return { data: user.login, type: 'String' };
      if (field === 'id') return { data: String(user.id), type: 'ID' };
      return undefined;
    }
    case 'Ref': {
      const ref = value as { name: string };
      if (field === 'name') return { data: ref.name, type: 'String' };
      return undefined;
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'PullRequestFileConnection':
    case 'LabelConnection':
    case 'IssueCommentConnection': {
      const conn = value as { nodes: unknown[]; pageInfo?: Record<string, unknown>; totalCount?: number };
      if (field === 'nodes') {
        const nodeType = parentType === 'IssueConnection' ? 'Issue' : parentType === 'PullRequestConnection' ? 'PullRequest' : parentType === 'PullRequestFileConnection' ? 'PullRequestFile' : parentType === 'LabelConnection' ? 'Label' : 'IssueComment';
        return { data: conn.nodes, type: nodeType };
      }
      if (field === 'pageInfo') return { data: conn.pageInfo ?? { hasNextPage: false, endCursor: null }, type: 'PageInfo' };
      if (field === 'totalCount') return { data: conn.totalCount ?? conn.nodes.length, type: 'Int' };
      if (field === 'edges') {
        return { data: conn.nodes.map((node) => ({ node, cursor: null })), type: 'Edge' };
      }
      return undefined;
    }
    case 'PageInfo': {
      const page = value as Record<string, unknown>;
      if (field === 'hasNextPage') return { data: page.hasNextPage ?? false, type: 'Boolean' };
      if (field === 'endCursor') return { data: page.endCursor ?? null, type: 'String' };
      if (field === 'hasPreviousPage') return { data: page.hasPreviousPage ?? false, type: 'Boolean' };
      if (field === 'startCursor') return { data: page.startCursor ?? null, type: 'String' };
      return undefined;
    }
    case '__Type': {
      const t = value as { __gqlType: string; name: string; kind: string; fields: Array<{ name: string }>; enumValues: Array<{ name: string }> };
      if (field === 'name') return { data: t.name, type: 'String' };
      if (field === 'kind') return { data: t.kind, type: 'String' };
      if (field === 'fields') return { data: t.fields, type: 'Field' };
      if (field === 'enumValues') return { data: t.enumValues, type: 'EnumValue' };
      return undefined;
    }
    case 'Field':
    case 'EnumValue': {
      const item = value as { name: string };
      if (field === 'name') return { data: item.name, type: 'String' };
      return undefined;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      const payload = value as { issue?: Issue };
      if (field === 'issue') return { data: payload.issue ?? null, type: 'Issue' };
      return undefined;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      const payload = value as { pullRequest?: Pull };
      if (field === 'pullRequest') return { data: payload.pullRequest ?? null, type: 'PullRequest' };
      return undefined;
    }
    case 'AddCommentPayload': {
      const payload = value as { commentEdge?: { node: { id: string; body: string } } };
      if (field === 'commentEdge') return { data: payload.commentEdge ?? null, type: 'IssueCommentEdge' };
      return undefined;
    }
    case 'IssueCommentEdge': {
      const edge = value as { node: { id: string; body: string } };
      if (field === 'node') return { data: edge.node, type: 'IssueComment' };
      return undefined;
    }
    case 'IssueComment': {
      const comment = value as { id: string | number; body: string };
      if (field === 'id') return { data: String(comment.id), type: 'ID' };
      if (field === 'body') return { data: comment.body, type: 'String' };
      return undefined;
    }
    case 'PullRequestFile': {
      const file = value as { path: string };
      if (field === 'path') return { data: file.path, type: 'String' };
      return undefined;
    }
    case 'Label': {
      const label = value as Label;
      if (field === 'name') return { data: label.name, type: 'String' };
      if (field === 'color') return { data: label.color, type: 'String' };
      return undefined;
    }
    case 'Edge': {
      const edge = value as { node: unknown };
      if (field === 'node') return { data: edge.node, type: 'Issue' };
      if (field === 'cursor') return { data: null, type: 'String' };
      return undefined;
    }
    case '__Schema': {
      const schema = value as { queryType: { name: string }; mutationType: { name: string } };
      if (field === 'queryType') return { data: schema.queryType, type: '__Type' };
      if (field === 'mutationType') return { data: schema.mutationType, type: '__Type' };
      return undefined;
    }
    default:
      return undefined;
  }
}

function findRepoOfPull(pull: Pull): Repo | null {
  for (const repo of repos.values()) {
    if (repo.pulls.includes(pull)) return repo;
  }
  return null;
}

function executeGraphqlOp(op: { query?: string; variables?: Record<string, unknown> }): Json {
  const query = typeof op.query === 'string' ? op.query : '';
  const variables = op.variables ?? {};
  let parsed: GqlOp;
  try {
    parsed = new GqlParser(query).parseOperation();
  } catch (err) {
    return { errors: [{ message: `GraphQL parse error: ${err instanceof Error ? err.message : String(err)}` }] };
  }
  const state: ExecState = { errors: [] };
  const rootType = parsed.operation === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelection(rootType, null, parsed.selections, {}, variables, parsed.varDefaults, state);
  const result: Json = { data };
  if (state.errors.length > 0) result.errors = state.errors;
  return result;
}

function handleGraphql(ctx: ReqCtx): void {
  if (ctx.method !== 'POST') {
    sendError(ctx, 405, 'Method Not Allowed');
    return;
  }
  if (ctx.jsonError) {
    sendError(ctx, 400, 'malformed JSON body');
    return;
  }
  const parsed = ctx.json;
  if (parsed === null) {
    sendError(ctx, 400, 'GraphQL request body must be a JSON object');
    return;
  }
  if (Array.isArray(parsed)) {
    const results = (parsed as unknown[]).map((item) => {
      if (item !== null && typeof item === 'object') return executeGraphqlOp(item as { query?: string; variables?: Record<string, unknown> });
      return { errors: [{ message: 'invalid operation' }] };
    });
    sendJson(ctx, 200, results);
    return;
  }
  sendJson(ctx, 200, executeGraphqlOp(parsed as unknown as { query?: string; variables?: Record<string, unknown> }));
}

// -------------------------------------------------------------------------------------------
// MCP (JSON-RPC 2.0, Streamable HTTP)
// -------------------------------------------------------------------------------------------

const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Json }> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const SERVER_INFO = { name: SERVER_NAME, version: SERVER_VERSION };
const SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25'];

function rpcResult(ctx: ReqCtx, id: unknown, result: unknown): void {
  sendJson(ctx, 200, { jsonrpc: '2.0', id: id ?? null, result });
}

function rpcError(ctx: ReqCtx, id: unknown, code: number, message: string, httpStatus = 200): void {
  sendJson(ctx, httpStatus, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

function toolTextResult(obj: unknown): Json {
  const text = JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj };
}

function toolErrorResult(message: string): Json {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(name: string, args: Record<string, unknown>): Json {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (!tool) return { __rpcError: -32601, __message: `Method not found: ${name}` } as unknown as Json;
  const required = (tool.inputSchema.required as string[]) ?? [];
  for (const key of required) {
    if (args[key] === undefined || args[key] === null || args[key] === '') {
      return { __rpcError: -32602, __message: `Missing required argument: ${key}` } as unknown as Json;
    }
  }
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (lookupRepo(VIEWER_LOGIN, repoName)) return toolErrorResult(`Repository ${repoName} already exists`);
    const repo = createRepo(VIEWER_LOGIN, repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
    return toolTextResult(repoJson(repo));
  }
  if (name === 'get_repo') {
    const repo = resolveRepo({} as ReqCtx, String(args.owner), String(args.repo));
    if (!repo) return toolErrorResult('Repository not found');
    return toolTextResult(repoJson(repo));
  }
  if (name === 'create_issue') {
    const repo = resolveRepo({} as ReqCtx, String(args.owner), String(args.repo));
    if (!repo) return toolErrorResult('Repository not found');
    const number = repo.nextIssue++;
    const issue: Issue = {
      number,
      id: globalId('I', `${repo.owner}/${repo.name}#${number}`),
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      comments: [],
      jsonCache: null,
    };
    repo.issues.push(issue);
    return toolTextResult(issueJson(issue, repo));
  }
  if (name === 'list_issues') {
    const repo = resolveRepo({} as ReqCtx, String(args.owner), String(args.repo));
    if (!repo) return toolErrorResult('Repository not found');
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = state === 'all' ? repo.issues : repo.issues.filter((i) => i.state === state);
    return toolTextResult({ issues: list.map((issue) => issueJson(issue, repo)) });
  }
  if (name === 'create_pull_request') {
    const repo = resolveRepo({} as ReqCtx, String(args.owner), String(args.repo));
    if (!repo) return toolErrorResult('Repository not found');
    const head = String(args.head);
    const base = String(args.base);
    const headSha = refShaOf(repo, head);
    const baseSha = refShaOf(repo, base);
    if (headSha === undefined || baseSha === undefined) return toolErrorResult('head or base branch not found');
    const number = repo.nextPull++;
    const pull: Pull = {
      number,
      id: globalId('PR', `${repo.owner}/${repo.name}#${number}`),
      title: String(args.title),
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      head,
      base,
      headSha,
      baseSha,
    };
    repo.pulls.push(pull);
    return toolTextResult(pullJson(pull, repo));
  }
  if (name === 'merge_pull_request') {
    const repo = resolveRepo({} as ReqCtx, String(args.owner), String(args.repo));
    if (!repo) return toolErrorResult('Repository not found');
    const pull = findPull(repo, Number(args.pull_number));
    if (!pull) return toolErrorResult('Pull request not found');
    if (pull.state !== 'open') return toolErrorResult('Pull request is already closed');
    const merged = mergePull(repo, pull);
    if (merged === null) return toolErrorResult('Merge conflict');
    return toolTextResult({ merged: true, sha: merged.sha, number: pull.number });
  }
  return toolErrorResult(`Unknown tool: ${name}`);
}

function handleMcp(ctx: ReqCtx): void {
  if (ctx.method === 'DELETE') {
    ctx.res.writeHead(200, { 'x-github-request-id': `req-${++requestCounter}`, 'content-length': 0 });
    ctx.res.end();
    return;
  }
  if (ctx.method !== 'POST') {
    sendError(ctx, 405, 'Method Not Allowed');
    return;
  }
  // Auth is checked before body parsing.
  if (!authorized(ctx)) {
    sendError(ctx, 401, 'Unauthorized');
    return;
  }
  let parsed: unknown;
  try {
    parsed = ctx.body.length === 0 ? null : JSON.parse(ctx.body.toString('utf8'));
  } catch {
    rpcError(ctx, null, -32700, 'Parse error', 400);
    return;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    rpcError(ctx, null, -32600, 'Invalid Request', 400);
    return;
  }
  const request = parsed as { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  const id = request.id ?? null;
  const method = typeof request.method === 'string' ? request.method : '';
  const params = (request.params ?? {}) as Record<string, unknown>;
  if (method.startsWith('notifications/')) {
    ctx.res.writeHead(202, { 'x-github-request-id': `req-${++requestCounter}`, 'content-length': 0 });
    ctx.res.end();
    return;
  }
  if (method === 'server/discover') {
    rpcResult(ctx, id, {
      supportedVersions: SUPPORTED_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
      _meta: { serverInfo: SERVER_INFO },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const protocolVersion = SUPPORTED_VERSIONS.includes(requested) ? requested : SUPPORTED_VERSIONS[0];
    rpcResult(ctx, id, { protocolVersion, capabilities: { tools: {} }, serverInfo: SERVER_INFO });
    return;
  }
  if (method === 'ping') {
    rpcResult(ctx, id, {});
    return;
  }
  if (method === 'tools/list') {
    rpcResult(ctx, id, { tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const result = mcpCallTool(name, args);
    const rpcErr = (result as unknown as { __rpcError?: number; __message?: string }).__rpcError;
    if (rpcErr !== undefined) {
      rpcError(ctx, id, rpcErr, (result as unknown as { __message?: string }).__message ?? 'error');
      return;
    }
    rpcResult(ctx, id, result);
    return;
  }
  rpcError(ctx, id, -32601, `Method not found: ${method}`);
}

// -------------------------------------------------------------------------------------------
// top-level dispatcher and lifecycle
// -------------------------------------------------------------------------------------------

function handleRequest(req: MiniReq, body: Buffer, res: MiniRes): void {
  // Manual URL split: `new URL` + URLSearchParams cost ~1.3µs per request and
  // the query is rarely needed (only info/refs `service` on the hot paths).
  // Absolute-form URLs (proxy-style) fall back to the URL constructor.
  // The body arrives whole from the TCP parser: no stream read, no await, fully synchronous.
  if (body.length > 64 * 1024 * 1024) {
    const tooBig: ReqCtx = {
      req, res, method: req.method, pathname: '/', queryString: '', queryCache: null,
      segments: [], body: EMPTY_BUFFER, json: null, jsonError: false,
    };
    sendError(tooBig, 413, 'Request body too large');
    return;
  }
  const rawUrl = req.url ?? '/';
  let pathname: string;
  let queryString = '';
  if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
    const u = new URL(rawUrl);
    pathname = u.pathname;
    queryString = u.search.slice(1);
  } else {
    const qi = rawUrl.indexOf('?');
    pathname = qi < 0 ? rawUrl : rawUrl.slice(0, qi);
    queryString = qi < 0 ? '' : rawUrl.slice(qi + 1);
  }
  const ctx: ReqCtx = {
    req,
    res,
    method: req.method ?? 'GET',
    pathname,
    queryString,
    queryCache: null,
    segments: parsePath(pathname),
    body,
    json: null,
    jsonError: false,
  };
  // Parse a JSON body once for the JSON endpoints.
  const contentType = req.headers['content-type'] ?? '';
  const isJson = contentType.includes('application/json') || contentType.includes('application/vnd.github');
  if (ctx.body.length > 0 && isJson) {
    try {
      const parsed: unknown = JSON.parse(ctx.body.toString('utf8'));
      if (parsed !== null && typeof parsed === 'object') ctx.json = parsed as Json;
      else if (Array.isArray(parsed)) ctx.json = parsed as unknown as Json;
    } catch {
      ctx.jsonError = true;
    }
  }
  try {
    if (ctx.pathname === '/healthz') {
      if (ctx.method !== 'GET') {
        sendError(ctx, 405, 'Method Not Allowed');
        return;
      }
      sendJson(ctx, 200, { ok: true });
      return;
    }
    if (ctx.pathname === '/api/graphql') {
      if (!authorized(ctx)) {
        sendError(ctx, 401, 'Unauthorized');
        return;
      }
      handleGraphql(ctx);
      return;
    }
    if (ctx.pathname === '/mcp') {
      handleMcp(ctx);
      return;
    }
    if (ctx.segments.length >= 2 && ctx.segments[0] === 'api' && ctx.segments[1] === 'v3') {
      // /api/v3/ and /api/v3/meta are public; everything else needs the token.
      const isPublic = (ctx.segments.length === 2) || (ctx.segments.length === 3 && ctx.segments[2] === 'meta');
      if (!isPublic && !authorized(ctx)) {
        sendError(ctx, 401, 'Unauthorized');
        return;
      }
      if (dispatchRest(ctx)) return;
      sendError(ctx, 404, 'Not Found');
      return;
    }
    if (dispatchGit(ctx)) return;
    sendError(ctx, 404, 'Not Found');
  } catch (err) {
    // A handler must never take the server down with it.
    if (!res.writableEnded) {
      try {
        sendError(ctx, 500, err instanceof Error ? err.message : 'Internal Server Error');
      } catch {
        res.destroy();
      }
    }
  }
}

async function registerAndWait(): Promise<void> {
  const rawEnvUrl = process.env.MAKEFUN_ENV_URL ?? '';
  if (rawEnvUrl === '') return;
  const envUrl = rawEnvUrl.replace(/\/+$/, '');
  const port = (globalThis as unknown as { __forgePort: number }).__forgePort;
  const register = async (): Promise<void> => {
    const response = await fetch(`${envUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ port }),
    });
    if (!response.ok) throw new Error(`register failed: ${response.status}`);
  };
  // The environment is up before the program starts, but a transient failure here
  // would cost the whole trial, so retry instead of exiting.
  let registered = false;
  for (let attempt = 0; attempt < 30 && !registered; attempt += 1) {
    try {
      await register();
      registered = true;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  if (!registered) throw new Error('could not register with the environment');
  for (;;) {
    let done = false;
    try {
      const response = await fetch(`${envUrl}/done`);
      if (response.ok) {
        const data = (await response.json()) as { done?: boolean };
        done = data.done === true;
      }
    } catch {
      // A transient poll failure is not a reason to exit; keep polling.
    }
    if (done) return;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

/** One socket: parse complete requests off the byte stream, handle each synchronously, keep-alive. */
function handleSocket(socket: Socket): void {
  let buf = EMPTY_BUFFER;
  socket.on('data', (chunk: Buffer) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length > 64 * 1024 && buf.indexOf('\r\n\r\n') < 0) {
        socket.destroy();
        return;
      }
      const parsed = tryParseRequest(buf);
      if (parsed === null) return; // wait for more bytes
      buf = buf.subarray(parsed.consumed);
      const res = new MiniRes(socket);
      try {
        handleRequest(parsed, parsed.body, res);
      } catch {
        // handleRequest catches its own errors; this is only a backstop.
        if (!res.writableEnded) socket.destroy();
      }
      if (!parsed.keepAlive) {
        socket.end();
        return;
      }
      if (buf.length === 0) return;
    }
  });
  socket.on('error', () => {
    socket.destroy();
  });
}

async function main(): Promise<void> {
  const server = createServer(handleSocket);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  SERVER_PORT = port;
  (globalThis as unknown as { __forgePort: number }).__forgePort = port;
  // The environment may never set MAKEFUN_ENV_URL when run locally; in that case just serve.
  const envUrl = process.env.MAKEFUN_ENV_URL ?? '';
  if (envUrl !== '') {
    await registerAndWait();
    server.close();
    process.exit(0);
  }
  // Local run: stay up until killed.
  await new Promise<void>(() => undefined);
}

void main();
