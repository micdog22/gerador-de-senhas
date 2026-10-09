// Medidor de força para senhas digitadas, no espírito do zxcvbn.
//
// A ideia: quem ataca não testa combinações ao acaso. Primeiro vêm senhas vazadas,
// palavras, datas, sequências e caminhos no teclado. O medidor procura esses padrões,
// estima quantas tentativas cada um custa e escolhe a forma mais barata de "montar" a
// senha com eles (programação dinâmica). O resultado é uma estimativa em bits.

import { WORDS } from './wordlist.js';
import { COMMON } from './common.js';

const DICTIONARY = new Set(WORDS);
const COMMON_RANK = new Map(COMMON.map((w, i) => [w, i + 1]));
const LEET = { 4: 'a', '@': 'a', 3: 'e', 1: 'i', '!': 'i', 0: 'o', $: 's', 5: 's', 7: 't', '+': 't', 8: 'b', 9: 'g' };
const SHIFTED = { '!': '1', '@': '2', '#': '3', $: '4', '%': '5', '¨': '6', '^': '6', '&': '7', '*': '8', '(': '9', ')': '0' };
const SEPARATORS = ' -._';

export const BANDS = [
  { min: 0, label: 'Muito fraca' },
  { min: 25, label: 'Fraca' },
  { min: 40, label: 'Razoável' },
  { min: 60, label: 'Forte' },
  { min: 80, label: 'Muito forte' },
];

function binomial(n, k) {
  if (k < 0 || k > n) return 0;
  let r = 1;
  for (let i = 1; i <= k; i++) r = (r * (n - k + i)) / i;
  return r;
}

/** Variações de maiúsculas (regra do zxcvbn): "senha" 1, "Senha" ou "SENHA" 2, misturado mais. */
export function caseVariations(token) {
  const upper = (token.match(/\p{Lu}/gu) || []).length;
  const lower = (token.match(/\p{Ll}/gu) || []).length;
  if (!upper) return 1;
  const first = /^\p{Lu}[^\p{Lu}]*$/u.test(token);
  const last = /^[^\p{Lu}]*\p{Lu}$/u.test(token);
  if (first || last || !lower) return 2;
  let total = 0;
  for (let i = 1; i <= Math.min(upper, lower); i++) total += binomial(upper + lower, i);
  return total;
}

/** Desfaz trocas "leet" (s3nh@ vira senha). Retorna o texto e quantas trocas houve. */
export function unleet(text) {
  let subs = 0;
  let out = '';
  for (const ch of text) {
    if (LEET[ch] !== undefined) {
      out += LEET[ch];
      subs++;
    } else out += ch;
  }
  return { text: out, subs };
}

function cardinality(password) {
  let n = 0;
  if (/[a-z]/.test(password)) n += 26;
  if (/[A-Z]/.test(password)) n += 26;
  if (/[0-9]/.test(password)) n += 10;
  if (/[^a-zA-Z0-9\s\p{L}]/u.test(password)) n += 33;
  if (/\s/.test(password)) n += 1;
  if (/[^\x00-\x7F]/.test(password)) n += 100;
  return Math.max(n, 10);
}

// ---------- detectores ----------

function dictionaryMatches(password) {
  const out = [];
  const lower = password.toLowerCase();
  const n = password.length;
  for (let i = 0; i < n; i++) {
    for (let j = i + 2; j < Math.min(n, i + 30); j++) {
      const token = password.slice(i, j + 1);
      const raw = lower.slice(i, j + 1);
      const { text: plain, subs } = unleet(raw);
      const candidates = [[raw, 0]];
      if (subs > 0 && plain !== raw) candidates.push([plain, subs]);
      for (const [candidate, leet] of candidates) {
        const rank = COMMON_RANK.get(candidate);
        const variations = caseVariations(token) * (leet ? 2 ** Math.min(leet, 3) : 1);
        if (rank) out.push({ i, j, pattern: 'common', token, guesses: rank * variations, leet: leet > 0 });
        else if (candidate.length >= 4 && DICTIONARY.has(candidate)) {
          out.push({ i, j, pattern: 'word', token, guesses: WORDS.length * variations, leet: leet > 0 });
        }
      }
    }
  }
  return out;
}

function classOf(ch) {
  if (/[a-z]/.test(ch)) return 'lower';
  if (/[A-Z]/.test(ch)) return 'upper';
  if (/[0-9]/.test(ch)) return 'digit';
  return null;
}

function sequenceMatches(password) {
  const out = [];
  const n = password.length;
  let i = 0;
  while (i < n - 2) {
    const cls = classOf(password[i]);
    const delta = password.charCodeAt(i + 1) - password.charCodeAt(i);
    let j = i + 1;
    if (cls && (delta === 1 || delta === -1) && classOf(password[j]) === cls) {
      while (j + 1 < n && classOf(password[j + 1]) === cls && password.charCodeAt(j + 1) - password.charCodeAt(j) === delta) j++;
    }
    if (j - i + 1 >= 3) {
      const first = password[i];
      let base = 'aAzZ019'.includes(first) ? 4 : cls === 'digit' ? 10 : 26;
      if (delta < 0) base *= 2;
      out.push({ i, j, pattern: 'sequence', token: password.slice(i, j + 1), guesses: base * (j - i + 1) });
      i = j + 1;
    } else i++;
  }
  return out;
}

function repeatMatches(password, estimate) {
  const out = [];
  const n = password.length;
  for (let i = 0; i < n; i++) {
    let best = null;
    for (let u = 1; u <= Math.min(32, (n - i) / 2); u++) {
      const unit = password.slice(i, i + u);
      let reps = 1;
      while (password.slice(i + reps * u, i + (reps + 1) * u) === unit) reps++;
      const len = reps * u;
      if (reps >= 2 && len >= 3 && (!best || len > best.len)) best = { u, reps, len, unit };
    }
    if (best) {
      const unitGuesses = best.u === 1 ? cardinality(best.unit) : 2 ** estimate(best.unit).bits;
      out.push({ i, j: i + best.len - 1, pattern: 'repeat', token: password.slice(i, i + best.len), guesses: unitGuesses * best.reps });
    }
  }
  return out;
}

// Teclado no padrão QWERTY (com a linha do ABNT2), cada linha deslocada como no teclado real.
const ROWS = [['1234567890-=', 0], ['qwertyuiop', 0.5], ['asdfghjklç', 0.75], ['zxcvbnm,.;', 1.25]];
const KEY_POS = new Map();
ROWS.forEach(([keys, offset], row) => [...keys].forEach((k, col) => KEY_POS.set(k, { x: col + offset, y: row })));

function keyOf(ch) {
  const lower = ch.toLowerCase();
  return SHIFTED[lower] || lower;
}

function adjacent(a, b) {
  const p = KEY_POS.get(keyOf(a));
  const q = KEY_POS.get(keyOf(b));
  if (!p || !q || (p.x === q.x && p.y === q.y)) return null;
  const dx = q.x - p.x;
  const dy = q.y - p.y;
  if (Math.abs(dy) > 1 || Math.abs(dx) > 1) return null;
  return `${Math.sign(dx)},${dy}`;
}

function keyboardMatches(password) {
  const out = [];
  const n = password.length;
  let i = 0;
  while (i < n - 3) {
    let j = i;
    let turns = 0;
    let dir = null;
    while (j + 1 < n) {
      const d = adjacent(password[j], password[j + 1]);
      if (!d) break;
      if (dir !== null && d !== dir) turns++;
      dir = d;
      j++;
    }
    if (j - i + 1 >= 4) {
      out.push({ i, j, pattern: 'keyboard', token: password.slice(i, j + 1), guesses: 44 * (j - i + 1) * (turns + 1) ** 2 });
      i = j + 1;
    } else i++;
  }
  return out;
}

function dateMatches(password) {
  const out = [];
  const add = (m, guesses) => out.push({ i: m.index, j: m.index + m[0].length - 1, pattern: 'date', token: m[0], guesses });
  for (const m of password.matchAll(/(?<!\d)(19[0-9]{2}|20[0-3][0-9])(?!\d)/g)) add(m, 140);
  const dateRe = /(?<!\d)(\d{1,2})([/.-]?)(\d{1,2})\2(\d{4}|\d{2})(?!\d)/g;
  for (const m of password.matchAll(dateRe)) {
    const d = Number(m[1]);
    const mo = Number(m[3]);
    if (d >= 1 && d <= 31 && mo >= 1 && mo <= 12) add(m, 365 * (m[4].length === 4 ? 140 : 100) * (m[2] ? 4 : 1));
  }
  return out;
}

function separatorMatches(password) {
  const out = [];
  for (let i = 1; i < password.length - 1; i++) {
    if (SEPARATORS.includes(password[i]) && /\p{L}/u.test(password[i - 1]) && /\p{L}/u.test(password[i + 1])) {
      out.push({ i, j: i, pattern: 'separator', token: password[i], guesses: 4 });
    }
  }
  return out;
}

// ---------- estimativa ----------

/**
 * Estima a força de uma senha. Retorna { bits, score (0 a 4), label, sequence } onde
 * sequence é a lista de pedaços escolhidos (padrões e trechos "aleatórios").
 */
export function estimate(password) {
  const pw = String(password ?? '');
  const n = pw.length;
  if (!n) return { bits: 0, score: 0, label: BANDS[0].label, sequence: [] };
  const bruteBits = Math.log2(cardinality(pw));
  const matches = [
    ...dictionaryMatches(pw), ...sequenceMatches(pw), ...repeatMatches(pw, estimate), ...keyboardMatches(pw),
    ...dateMatches(pw), ...separatorMatches(pw),
  ];
  const endingAt = Array.from({ length: n }, () => []);
  for (const m of matches) endingAt[m.j].push(m);

  // best[k]: menor custo (em bits) para cobrir os k primeiros caracteres
  const best = new Array(n + 1).fill(Infinity);
  const back = new Array(n + 1).fill(null);
  best[0] = 0;
  for (let k = 1; k <= n; k++) {
    const brute = best[k - 1] + bruteBits;
    if (brute < best[k]) {
      best[k] = brute;
      back[k] = { i: k - 1, j: k - 1, pattern: 'bruteforce', token: pw[k - 1] };
    }
    for (const m of endingAt[k - 1]) {
      // cada padrão a mais custa 1 bit: quem ataca também precisa adivinhar a estrutura
      // (separadores entre palavras já fazem parte da estrutura de uma frase-senha)
      const penalty = m.pattern === 'separator' ? 0 : 1;
      const cost = best[m.i] + Math.log2(Math.max(1, m.guesses)) + penalty;
      if (cost < best[k]) {
        best[k] = cost;
        back[k] = m;
      }
    }
  }
  const sequence = [];
  for (let k = n; k > 0;) {
    const m = back[k];
    const last = sequence[0];
    if (m.pattern === 'bruteforce' && last && last.pattern === 'bruteforce') {
      last.i = m.i;
      last.token = m.token + last.token;
    } else sequence.unshift({ ...m });
    k = m.i;
  }
  const bits = Math.max(0, best[n]);
  const band = [...BANDS].reverse().find((b) => bits >= b.min);
  return { bits, score: BANDS.indexOf(band), label: band.label, sequence };
}

const FEEDBACK = {
  common: 'Esta senha (ou um pedaço dela) está entre as mais usadas. Quem ataca tenta essas primeiro.',
  word: 'Palavras do dicionário sozinhas são fáceis de adivinhar. Junte várias palavras sorteadas ou use o gerador.',
  sequence: 'Sequências como abc ou 1234 estão entre as primeiras tentativas.',
  repeat: 'Repetições como aaa ou abcabc ajudam pouco.',
  keyboard: 'Caminhos no teclado, como qwerty ou asdf, são conhecidos dos programas de ataque.',
  date: 'Datas e anos (aniversários, por exemplo) são muito usados e fáceis de adivinhar.',
  leet: 'Trocar letras por números ou símbolos (s3nh@) não engana os programas de ataque.',
};

/** Avisos e sugestões em português para o resultado de estimate(). */
export function feedback(password, result) {
  const pw = String(password ?? '');
  if (!pw) return ['Digite uma senha para ver a análise.'];
  const tips = [];
  const patterns = new Set(result.sequence.map((s) => s.pattern));
  for (const p of ['common', 'word', 'sequence', 'repeat', 'keyboard', 'date']) if (patterns.has(p)) tips.push(FEEDBACK[p]);
  if (result.sequence.some((s) => s.leet)) tips.push(FEEDBACK.leet);
  if (/^\p{Lu}[^\p{Lu}]+$/u.test(pw) && result.score < 3) tips.push('Letra maiúscula só no começo quase não ajuda: é a primeira coisa que os ataques testam.');
  if (pw.length < 12 && result.score < 4) tips.push('Use pelo menos 12 caracteres, ou uma frase-senha com 5 palavras ou mais.');
  if (result.score >= 3) tips.push('Boa senha. Use uma diferente em cada site e guarde num gerenciador de senhas.');
  return tips;
}

// ---------- tempo para quebrar ----------

export const SCENARIOS = [
  { id: 'online-limitado', rate: 100 / 3600, label: 'Ataque pela internet, com limite de tentativas', detail: 'cerca de 100 por hora' },
  { id: 'online', rate: 10, label: 'Ataque pela internet, sem limite', detail: '10 por segundo' },
  { id: 'offline-lento', rate: 1e4, label: 'Vazamento com hash lento (bcrypt, Argon2)', detail: '10 mil por segundo' },
  { id: 'offline-rapido', rate: 1e10, label: 'Vazamento com hash rápido (MD5, SHA-1) e placas de vídeo', detail: '10 bilhões por segundo' },
];

/** Tempo médio para achar a senha: metade do espaço de tentativas dividido pela velocidade. */
export function crackSeconds(bits, rate) {
  return 2 ** (bits - 1) / rate;
}

const YEAR = 365.25 * 24 * 3600;
const UNIVERSE = 13.8e9 * YEAR;

/** Duração por extenso: "instantâneo", "3 horas", "12 anos", "5 mil anos"... */
export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds >= UNIVERSE) return 'mais que a idade do universo';
  if (seconds < 1) return 'instantâneo';
  const units = [['ano', YEAR], ['mês', YEAR / 12], ['dia', 86400], ['hora', 3600], ['minuto', 60], ['segundo', 1]];
  for (const [name, size] of units) {
    if (seconds >= size) {
      const v = Math.floor(seconds / size);
      if (name === 'ano' && v >= 1000) {
        const big = [['bilhões', 1e9], ['milhões', 1e6], ['mil', 1e3]];
        for (const [word, f] of big) {
          if (v >= f) {
            const x = Math.floor(v / f);
            const w = word === 'bilhões' && x === 1 ? 'bilhão' : word === 'milhões' && x === 1 ? 'milhão' : word;
            return `${x} ${w} de anos`.replace(' mil de anos', ' mil anos');
          }
        }
      }
      const plural = name === 'mês' ? 'meses' : `${name}s`;
      return `${v} ${v === 1 ? name : plural}`;
    }
  }
  return 'instantâneo';
}

export function crackTimes(bits) {
  return SCENARIOS.map((s) => ({ ...s, seconds: crackSeconds(bits, s.rate), text: formatDuration(crackSeconds(bits, s.rate)) }));
}
