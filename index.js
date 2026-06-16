const nativeBinding = require("bindings")("node-powhash.node");
const blake2 = require("blake2");

module.exports = nativeBinding;

const nativeRandomx = nativeBinding.randomx.bind(nativeBinding);
const nativeSetRandomxCacheSize = typeof nativeBinding.setRandomxCacheSize === "function"
  ? nativeBinding.setRandomxCacheSize.bind(nativeBinding)
  : null;
const RANDOMX_ALGO_NAMES = new Map([
  ["rx/0", 0],
  ["rx/2", "rx/2"],
  ["rx/arq", 2],
  ["rx/xla", 3],
  ["defyx", 3],
  ["panthera", 3],
  ["rx/wow", 17],
  ["rx/keva", 19],
  ["rx/graft", 20],
  ["rx/xeq", 22]
]);

let randomxCacheSize = 5;

module.exports.setRandomxCacheSize = function(size) {
  if (!Number.isInteger(size) || size < 1 || size > 256) {
    throw new RangeError("RandomX cache size must be an integer between 1 and 256");
  }
  if (nativeSetRandomxCacheSize) nativeSetRandomxCacheSize(size);
  randomxCacheSize = size;
};

module.exports.getRandomxCacheSize = function() {
  return randomxCacheSize;
};

module.exports.randomx = function(data, seedHash, algo = 0) {
  let resolved = algo;
  if (typeof algo === "string") {
    if (!RANDOMX_ALGO_NAMES.has(algo)) {
      throw new Error(`Unsupported RandomX algo: ${algo}`);
    }
    resolved = RANDOMX_ALGO_NAMES.get(algo);
  }
  return nativeRandomx(data, seedHash, resolved);
};

function bigIntToBufferBE(value, width) {
  if (typeof value !== "bigint") {
    throw new TypeError("value must be a bigint");
  }

  const buffer = Buffer.alloc(width);
  let remaining = value;

  for (let offset = width - 1; offset >= 0; offset -= 1) {
    buffer[offset] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }

  if (remaining !== 0n) {
    throw new RangeError("value does not fit in the requested width");
  }

  return buffer;
}

function bufferToBigIntBE(buffer) {
  let value = 0n;

  for (const byte of buffer) {
    value = (value << 8n) | BigInt(byte);
  }

  return value;
}

const M = Buffer.alloc(1024 * 8);
for (let i = 0; i < 1024; i += 1) {
  M.writeBigUInt64BE(BigInt(i), i * 8);
}

const NBase                  = 2n ** 26n;
const IncreaseStart          = 600 * 1024;
const IncreasePeriodForN     = 50 * 1024;
const NIncreasementHeightMax = 9216000;

const N = height => {
  height = Math.min(NIncreasementHeightMax, height);
  if (height < IncreaseStart) {
    return NBase;
  } else if(height >= NIncreasementHeightMax){
    return 2147387550n;
  } else {
    let res = NBase;
    let iterationsNumber = Math.floor((height - IncreaseStart) / IncreasePeriodForN) + 1;
    for (let i = 0; i < iterationsNumber; i++) {
      res = res / BigInt(100) * BigInt(105);
    }
    return res;
  }
}

function blake2b(seed) {
  const h = blake2.createHash("blake2b", { digestLength: 32 });
  h.update(seed);
  return h.digest();
}

function genIndexes(seed, height) {
  const hash = blake2b(seed);
  const extendedHash = new Uint8Array(hash.length * 2);
  extendedHash.__proto__ = hash.__proto__;
  extendedHash.set(hash);
  extendedHash.set(hash, hash.length);
  return Array.from({length: 32}).map((_, index) => extendedHash.readUIntBE(index, 4) % parseInt(N(height)))
}

module.exports.autolykos2_hashes = function(coinbaseBuffer, height) {
  const h = bigIntToBufferBE(BigInt(height), 4);
  const i = bigIntToBufferBE(bufferToBigIntBE(blake2b(coinbaseBuffer).slice(24, 32)) % N(height), 4);
  const e = blake2b(Buffer.concat([i, h, M])).slice(1, 32);
  const J = genIndexes(Buffer.concat([e, coinbaseBuffer]), height).map(item => bigIntToBufferBE(BigInt(item), 4));
  const f = J.map(item => bufferToBigIntBE(blake2b(Buffer.concat([item, h, M])).slice(1, 32))).reduce((a, b) => a + b);
  const hash = bigIntToBufferBE(f, 32);

  return [ hash, blake2b(hash) ];
};
