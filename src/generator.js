// Geração de senhas e frases-senha, com a entropia calculada exatamente.

import { WORDS } from './wordlist.js';

export const CLASSES = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%&*()-_=+[]{}<>?/:;.,~^',
};

// Caracteres fáceis de confundir na leitura (I, l e 1; O, 0 e o).
export const AMBIGUOUS = 'Il1O0o';

export const SEPARATORS = { hifen: '-', espaco: ' ', ponto: '.', sublinhado: '_', nenhum: '' };

/** Classes escolhidas, já sem os caracteres ambíguos se for o caso. */
export function buildClasses({ lower = true, upper = true, digits = true, symbols = true, avoidAmbiguous = false } = {}) {
  const wanted = { lower, upper, digits, symbols };
  return Object.entries(CLASSES)
    .filter(([name]) => wanted[name])
    .map(([name, chars]) => ({ name, chars: avoidAmbiguous ? [...chars].filter((c) => !AMBIGUOUS.includes(c)).join('') : chars }));
}

/**
 * Quantas senhas diferentes existem com `length` caracteres das classes dadas.
 * Exigindo pelo menos um de cada classe, a conta usa inclusão e exclusão:
 *   soma, para cada subconjunto S de classes, de (-1)^|S| * (N - tamanho(S))^L
 * (N é o total de caracteres). Usa BigInt porque os números passam de 2^53.
 */
export function passwordSpace(sizes, length, requireEach = true) {
  const total = sizes.reduce((a, b) => a + b, 0);
  const L = BigInt(length);
  if (!requireEach) return BigInt(total) ** L;
  let sum = 0n;
  const k = sizes.length;
  for (let mask = 0; mask < 1 << k; mask++) {
    let removed = 0;
    let bits = 0;
    for (let i = 0; i < k; i++) {
      if (mask & (1 << i)) {
        removed += sizes[i];
        bits++;
      }
    }
    const term = BigInt(total - removed) ** L;
    sum += bits % 2 ? -term : term;
  }
  return sum;
}

/** log2 de um BigInt positivo (com precisão de double). */
export function log2Big(n) {
  if (n <= 0n) return -Infinity;
  const s = n.toString(2);
  if (s.length <= 53) return Math.log2(Number(n));
  return Math.log2(parseInt(s.slice(0, 53), 2)) + (s.length - 53);
}

export function passwordEntropy(options) {
  const classes = buildClasses(options);
  if (!classes.length) return 0;
  const length = options.length ?? 16;
  const requireEach = options.requireEach ?? true;
  if (requireEach && length < classes.length) return 0;
  return log2Big(passwordSpace(classes.map((c) => c.chars.length), length, requireEach));
}

/**
 * Gera uma senha. Com `requireEach`, sorteia de novo enquanto faltar alguma classe:
 * isso mantém a distribuição uniforme entre todas as senhas válidas (ao contrário de
 * "forçar" um caractere de cada tipo em posições fixas).
 */
export function generatePassword(options, rng) {
  const length = options.length ?? 16;
  const requireEach = options.requireEach ?? true;
  const classes = buildClasses(options);
  if (!classes.length) throw new Error('Escolha pelo menos um tipo de caractere.');
  if (!Number.isInteger(length) || length < 4 || length > 128) throw new RangeError('O tamanho vai de 4 a 128.');
  if (requireEach && length < classes.length) throw new RangeError('A senha é curta demais para ter um caractere de cada tipo.');
  const alphabet = classes.map((c) => c.chars).join('');
  for (let attempt = 0; attempt < 10000; attempt++) {
    let out = '';
    for (let i = 0; i < length; i++) out += alphabet[rng.int(alphabet.length)];
    if (!requireEach || classes.every((c) => [...out].some((ch) => c.chars.includes(ch)))) return out;
  }
  throw new Error('Não foi possível gerar a senha.');
}

/**
 * Entropia da frase-senha: cada palavra vale log2(tamanho da lista); uma palavra em
 * maiúsculas sorteada soma log2(número de palavras); um algarismo em posição sorteada
 * soma log2(10) + log2(número de palavras).
 */
export function passphraseEntropy({ words = 6, capitalize = 'none', digit = false } = {}, listSize = WORDS.length) {
  let bits = words * Math.log2(listSize);
  if (capitalize === 'random') bits += Math.log2(words);
  if (digit) bits += Math.log2(10) + Math.log2(words);
  return bits;
}

const capitalizeFirst = (w) => w.charAt(0).toUpperCase() + w.slice(1);

/**
 * Gera uma frase-senha. Opções: words (3 a 12), separator, capitalize ('none',
 * 'first' para iniciais maiúsculas, 'random' para uma palavra toda em maiúsculas) e
 * digit (um algarismo no fim de uma palavra sorteada).
 */
export function generatePassphrase({ words = 6, separator = '-', capitalize = 'none', digit = false } = {}, rng, list = WORDS) {
  if (!Number.isInteger(words) || words < 3 || words > 12) throw new RangeError('Use de 3 a 12 palavras.');
  const chosen = Array.from({ length: words }, () => list[rng.int(list.length)]);
  let out = chosen.map((w) => (capitalize === 'first' ? capitalizeFirst(w) : w));
  if (capitalize === 'random') {
    const i = rng.int(words);
    out[i] = out[i].toUpperCase();
  }
  if (digit) {
    const i = rng.int(words);
    out[i] += String(rng.int(10));
  }
  return out.join(separator);
}
