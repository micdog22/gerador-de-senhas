import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { sha1Bytes, sha1Hex, toHex, splitHash, parseRange, checkPwned, RANGE_URL } from '../src/hibp.js';

const PASSWORD_HASH = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'; // SHA-1 de "password"

test('SHA-1: vetores de teste conhecidos', () => {
  const vectors = {
    '': 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709',
    abc: 'A9993E364706816ABA3E25717850C26C9CD0D89D',
    password: PASSWORD_HASH,
    'The quick brown fox jumps over the lazy dog': '2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12',
  };
  for (const [text, hex] of Object.entries(vectors)) {
    assert.equal(toHex(sha1Bytes(new TextEncoder().encode(text))), hex, JSON.stringify(text));
  }
});

test('SHA-1 em JavaScript puro confere com o node:crypto (bordas de bloco e UTF-8)', () => {
  let seed = 7;
  const rand = () => (seed = (seed * 1103515245 + 12345) >>> 0) >>> 24;
  for (const len of [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000]) {
    const bytes = new Uint8Array(len).map(rand);
    assert.equal(toHex(sha1Bytes(bytes)), createHash('sha1').update(bytes).digest('hex').toUpperCase(), `tamanho ${len}`);
  }
  for (const text of ['senha', 'São Paulo, coração', 'emoji 🔐 e acentuação']) {
    assert.equal(toHex(sha1Bytes(new TextEncoder().encode(text))), createHash('sha1').update(text, 'utf8').digest('hex').toUpperCase());
  }
});

test('sha1Hex: com e sem crypto.subtle dá o mesmo resultado', async () => {
  assert.equal(await sha1Hex('password'), PASSWORD_HASH);
  assert.equal(await sha1Hex('password', { subtle: null }), PASSWORD_HASH);
  assert.equal(await sha1Hex('coração', { subtle: null }), await sha1Hex('coração'));
});

test('splitHash: só os 5 primeiros dígitos saem do aparelho', () => {
  assert.deepEqual(splitHash(PASSWORD_HASH), { prefix: '5BAA6', suffix: '1E4C9B93F3F0682250B6CF8331B7EE68FD8' });
  assert.deepEqual(splitHash(PASSWORD_HASH.toLowerCase()).prefix, '5BAA6');
  assert.throws(() => splitHash('123'), /inválido/);
  assert.throws(() => splitHash('Z'.repeat(40)), /inválido/);
});

test('parseRange: acha o sufixo, ignora maiúsculas, CRLF e linhas de enchimento', () => {
  const body = [
    '0018A45C4D1DEF81644B54AB7F969B88D65:1',
    '1E4C9B93F3F0682250B6CF8331B7EE68FD8:52372427',
    '011053FD0102E94D6AE2F8B83D76FAF94F6:0',
  ].join('\r\n');
  assert.equal(parseRange(body, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 52372427);
  assert.equal(parseRange(body, '1e4c9b93f3f0682250b6cf8331b7ee68fd8'), 52372427);
  assert.equal(parseRange(body, '011053FD0102E94D6AE2F8B83D76FAF94F6'), 0); // enchimento
  assert.equal(parseRange(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), 0);
  assert.equal(parseRange('', 'ABC'), 0);
});

function mockFetch(response) {
  const calls = [];
  const fn = async (url, options) => {
    calls.push({ url, options });
    if (response instanceof Error) throw response;
    return response;
  };
  return { fn, calls };
}

const ok = (body) => ({ ok: true, status: 200, text: async () => body });

test('checkPwned: envia só o prefixo, com Add-Padding, e conta as ocorrências', async () => {
  const { fn, calls } = mockFetch(ok('1E4C9B93F3F0682250B6CF8331B7EE68FD8:52372427\r\nAAAAA:0'));
  const result = await checkPwned('password', { fetchFn: fn });
  assert.deepEqual(result, { count: 52372427, prefix: '5BAA6' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${RANGE_URL}5BAA6`);
  assert.equal(calls[0].options.headers['Add-Padding'], 'true');
  assert.equal(calls[0].options.method, 'GET');
  const sent = JSON.stringify(calls[0]);
  assert.equal(sent.includes('password'.toUpperCase()) || sent.includes('"password"'), false);
  assert.equal(sent.includes('1E4C9B93F3F0682250B6CF8331B7EE68FD8'), false);
  assert.equal(sent.includes(PASSWORD_HASH), false);
  assert.equal(calls[0].url.length, RANGE_URL.length + 5);
});

test('checkPwned: senha que não aparece na resposta conta zero', async () => {
  const { fn } = mockFetch(ok('0018A45C4D1DEF81644B54AB7F969B88D65:3'));
  assert.equal((await checkPwned('uma senha bem diferente', { fetchFn: fn })).count, 0);
});

test('checkPwned: erros em português e cancelamento repassado', async () => {
  await assert.rejects(checkPwned('', { fetchFn: async () => ok('') }), /Digite uma senha/);
  await assert.rejects(checkPwned('x', { fetchFn: mockFetch({ ok: false, status: 503, text: async () => '' }).fn }), /erro 503/);
  await assert.rejects(checkPwned('x', { fetchFn: mockFetch(new TypeError('Failed to fetch')).fn }), /Não foi possível falar com o serviço/);
  const abort = new Error('cancelado');
  abort.name = 'AbortError';
  await assert.rejects(checkPwned('x', { fetchFn: mockFetch(abort).fn }), { name: 'AbortError' });
});

test('checkPwned: funciona também sem crypto.subtle', async () => {
  const { fn, calls } = mockFetch(ok(''));
  await checkPwned('password', { fetchFn: fn, subtle: null });
  assert.equal(calls[0].url, `${RANGE_URL}5BAA6`);
});
