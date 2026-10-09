// Sorteio uniforme de inteiros com crypto.getRandomValues e amostragem por rejeição.
//
// O jeito ingênuo, x % n com x de 32 bits, tem viés: 2^32 não é múltiplo de n, então os
// primeiros (2^32 mod n) resultados aparecem uma vez a mais. A correção é descartar os
// valores do "pedaço que sobra" no topo do intervalo e sortear de novo.

export const UINT32_RANGE = 0x100000000; // 2^32

/**
 * Limite de aceitação para sortear em [0, max): o maior múltiplo de max que cabe em 2^32.
 * Valores sorteados a partir dele são descartados.
 */
export function rejectionLimit(max) {
  if (!Number.isInteger(max) || max < 1 || max > UINT32_RANGE) {
    throw new RangeError('max precisa ser um inteiro entre 1 e 2^32');
  }
  return UINT32_RANGE - (UINT32_RANGE % max);
}

/**
 * Cria um sorteador a partir de uma fonte que preenche Uint32Array (em produção,
 * crypto.getRandomValues; nos testes, uma fonte controlada).
 */
export function createRandom(fill) {
  const buffer = new Uint32Array(64);
  let pos = buffer.length;
  let draws = 0;
  let rejected = 0;
  const next = () => {
    if (pos >= buffer.length) {
      fill(buffer);
      pos = 0;
    }
    draws++;
    return buffer[pos++];
  };
  const int = (max) => {
    const limit = rejectionLimit(max);
    for (;;) {
      const x = next();
      if (x < limit) return x % max;
      rejected++;
    }
  };
  return {
    int,
    pick: (list) => list[int(list.length)],
    stats: () => ({ draws, rejected }),
  };
}

export function cryptoFill(buffer) {
  globalThis.crypto.getRandomValues(buffer);
  return buffer;
}

/** Sorteador seguro (crypto.getRandomValues). */
export function secureRandom() {
  return createRandom(cryptoFill);
}
