// "Verificar se vazou": consulta ao Have I Been Pwned por k-anonimato.
//
// A senha nunca sai do aparelho. O navegador calcula o SHA-1 dela (40 dígitos
// hexadecimais) e envia só os 5 primeiros. O serviço devolve todos os hashes vazados
// que começam com esse prefixo (centenas deles, com quantas vezes cada um apareceu), e
// a comparação com os 35 dígitos restantes acontece aqui. Como cada prefixo é comum a
// muitas senhas, o serviço não tem como saber qual delas foi consultada.

export const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/** SHA-1 em JavaScript puro (usado quando o crypto.subtle não está disponível). */
export function sha1Bytes(bytes) {
  const ml = bytes.length;
  const blocks = ((ml + 8) >> 6) + 1;
  const words = new Uint32Array(blocks * 16);
  for (let i = 0; i < ml; i++) words[i >> 2] |= bytes[i] << (24 - (i & 3) * 8);
  words[ml >> 2] |= 0x80 << (24 - (ml & 3) * 8);
  const bitLength = ml * 8;
  words[words.length - 1] = bitLength >>> 0;
  words[words.length - 2] = Math.floor(bitLength / 0x100000000);

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let off = 0; off < words.length; off += 16) {
    for (let t = 0; t < 16; t++) w[t] = words[off + t];
    for (let t = 16; t < 80; t++) {
      const x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
      w[t] = (x << 1) | (x >>> 31);
    }
    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for (let t = 0; t < 80; t++) {
      let f;
      let k;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) >>> 0;
      e = d;
      d = c;
      c = ((b << 30) | (b >>> 2)) >>> 0;
      b = a;
      a = temp;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }
  const out = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((h, i) => {
    out[i * 4] = h >>> 24;
    out[i * 4 + 1] = (h >>> 16) & 255;
    out[i * 4 + 2] = (h >>> 8) & 255;
    out[i * 4 + 3] = h & 255;
  });
  return out;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** SHA-1 do texto em UTF-8, em hexadecimal maiúsculo (como o serviço usa). */
export async function sha1Hex(text, { subtle = globalThis.crypto && globalThis.crypto.subtle } = {}) {
  const bytes = new TextEncoder().encode(String(text));
  if (subtle) return toHex(new Uint8Array(await subtle.digest('SHA-1', bytes)));
  return toHex(sha1Bytes(bytes));
}

/** Prefixo de 5 dígitos (o único que é enviado) e sufixo de 35 (que fica no aparelho). */
export function splitHash(hex) {
  const h = String(hex).toUpperCase();
  if (!/^[0-9A-F]{40}$/.test(h)) throw new Error('Hash SHA-1 inválido.');
  return { prefix: h.slice(0, 5), suffix: h.slice(5) };
}

/**
 * Procura o sufixo na resposta ("SUFIXO:CONTAGEM" por linha). Linhas de enchimento
 * (Add-Padding) têm contagem 0 e são ignoradas naturalmente.
 */
export function parseRange(body, suffix) {
  const want = String(suffix).toUpperCase();
  for (const line of String(body).split(/\r?\n/)) {
    const [hash, count] = line.trim().split(':');
    if (hash && hash.toUpperCase() === want) {
      const n = Number(count);
      return Number.isFinite(n) && n > 0 ? n : 0;
    }
  }
  return 0;
}

/**
 * Consulta o serviço. `fetchFn` pode ser trocado nos testes. Retorna { count, prefix }.
 * O cabeçalho Add-Padding pede respostas com tamanho parecido para qualquer prefixo,
 * para que nem o tamanho da resposta dê pistas.
 */
export async function checkPwned(password, { fetchFn = globalThis.fetch, signal, subtle } = {}) {
  if (!password) throw new Error('Digite uma senha primeiro.');
  const hex = await sha1Hex(password, subtle === undefined ? {} : { subtle });
  const { prefix, suffix } = splitHash(hex);
  let response;
  try {
    response = await fetchFn(`${RANGE_URL}${prefix}`, {
      method: 'GET',
      headers: { 'Add-Padding': 'true' },
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal,
    });
  } catch (err) {
    if (err && err.name === 'AbortError') throw err;
    throw new Error('Não foi possível falar com o serviço. Verifique a conexão e tente de novo.');
  }
  if (!response.ok) throw new Error(`O serviço respondeu com erro ${response.status}. Tente de novo mais tarde.`);
  return { count: parseRange(await response.text(), suffix), prefix };
}
