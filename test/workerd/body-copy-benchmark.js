// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

const BODY_BYTES = 25 * 1024 * 1024;
const COPIES_PER_BATCH = 20;
const ROUNDS = 7;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
let sink;

const candidates = [
  ["constructor", (source) => new Uint8Array(source)],
  ["view-and-slice", (source) => new Uint8Array(source.buffer, source.byteOffset, source.byteLength).slice()],
  [
    "intrinsic-constructor",
    (source) => {
      void Uint8Array.prototype.at.call(source, 0);
      const buffer = Reflect.get(typedArrayPrototype, "buffer", source);
      const byteOffset = Reflect.get(typedArrayPrototype, "byteOffset", source);
      const byteLength = Reflect.get(typedArrayPrototype, "byteLength", source);
      return new Uint8Array(new Uint8Array(buffer, byteOffset, byteLength));
    },
  ],
];

export default {
  test() {
    const source = benchmarkBody();
    for (const [, copy] of candidates) {
      for (let index = 0; index < 3; index += 1) {
        sink = copy(source);
      }
    }

    const samples = Object.fromEntries(candidates.map(([name]) => [name, []]));
    let checksum = 0;
    for (let round = 0; round < ROUNDS; round += 1) {
      for (let position = 0; position < candidates.length; position += 1) {
        const [name, copy] = candidates[(position + round) % candidates.length];
        const start = performance.now();
        for (let index = 0; index < COPIES_PER_BATCH; index += 1) {
          sink = copy(source);
          checksum += sink[0] + sink[sink.length >>> 1] + sink[sink.length - 1];
        }
        samples[name].push((performance.now() - start) / COPIES_PER_BATCH);
      }
    }

    console.log(
      JSON.stringify({
        bodyBytes: BODY_BYTES,
        copiesPerBatch: COPIES_PER_BATCH,
        rounds: ROUNDS,
        checksum,
        millisecondsPerCopy: Object.fromEntries(
          Object.entries(samples).map(([name, values]) => [name, summarize(values)])
        ),
      })
    );
  },
};

function benchmarkBody() {
  const pattern = new Uint8Array(64 * 1024);
  let state = 0x9e3779b9;
  for (let index = 0; index < pattern.length; index += 1) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    pattern[index] = state;
  }
  const body = new Uint8Array(BODY_BYTES);
  for (let offset = 0; offset < body.length; offset += pattern.length) {
    body.set(pattern.subarray(0, Math.min(pattern.length, body.length - offset)), offset);
  }
  return body;
}

function summarize(values) {
  const sorted = values.toSorted((left, right) => left - right);
  return {
    median: sorted[Math.floor(sorted.length / 2)],
    minimum: sorted[0],
    maximum: sorted[sorted.length - 1],
  };
}
