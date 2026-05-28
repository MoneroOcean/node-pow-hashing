"use strict";

const { spawn, spawnSync } = require("child_process");
const fs = require("fs/promises");
const path = require("path");

const multiHashing = require("..");

function fixturePath(file) {
  return path.join(__dirname, file);
}

async function readLines(file) {
  const text = await fs.readFile(fixturePath(file), "utf8");
  return text.split(/\r?\n/).filter(Boolean);
}

function splitOnce(line) {
  const index = line.indexOf(" ");
  if (index === -1) {
    throw new Error(`Unable to split line: ${line}`);
  }

  return [line.slice(0, index), line.slice(index + 1)];
}

function parseCnLine(line, encoding = "hex") {
  const [expected, input] = splitOnce(line);
  return { expected, input, encoding };
}

function parseCnLineWithHeight(line) {
  const [expected, rest] = splitOnce(line);
  const [input, height] = rest.split(" ");
  return { expected, input, height: Number.parseInt(height, 10) };
}

function parseRandomXLine(line) {
  const parts = line.split(" ");
  if (parts.length < 3) {
    throw new Error(`Unable to parse RandomX vector: ${line}`);
  }

  return {
    expected: parts[0],
    seed: parts[1],
    input: parts.slice(2).join(" "),
  };
}

function getMethod(methodName) {
  const method = multiHashing[methodName];
  if (typeof method !== "function") {
    throw new Error(`Missing method: ${methodName}`);
  }

  return method;
}

async function runVectorCase({ name, file, parseLine, execute, formatActual }, options = {}) {
  const lines = await readLines(file);
  let passed = 0;
  let failed = 0;

  for (const line of lines) {
    const testCase = parseLine(line);
    const actual = await execute(testCase);
    const expected = testCase.expected;

    if (actual !== expected) {
      failed += 1;
      console.error(`${name} mismatch: ${formatActual(testCase, actual)}`);
    } else {
      passed += 1;
    }
  }

  if (failed > 0) {
    throw new Error(`${failed}/${passed + failed} tests failed on: ${name}`);
  }
}

async function runCheckCase({ name, checks }, options = {}) {
  let passed = 0;
  let failed = 0;

  for (const check of checks) {
    const actual = await check.actual();
    if (actual !== check.expected) {
      failed += 1;
      console.error(`${name} mismatch: expected ${check.expected}, got ${actual}`);
    } else {
      passed += 1;
    }
  }

  if (failed > 0) {
    throw new Error(`${failed}/${passed + failed} tests failed on: ${name}`);
  }
}

function toHex(value) {
  if (Buffer.isBuffer(value)) {
    return value.toString("hex");
  }

  return value;
}

function vectorCase(definition) {
  return {
    ...definition,
    run: (options) => runVectorCase(definition, options),
  };
}

function checkCase(definition) {
  return {
    ...definition,
    run: (options) => runCheckCase(definition, options),
  };
}

const sharedAstroInput = Buffer.from(
  "0305a0dbd6bf05cf16e503f3a66f78007cbf34144332ecbfc22ed95c8700383b309ace1923a0964b00000008ba939a62724c0d7581fce5761e9d8a0e6a1c3f924fdd8493d1115649c05eb601",
  "hex"
);

const sharedArgonInput = sharedAstroInput;

const baseActiveCases = [
  checkCase({
    id: "randomx-ghostrider",
    name: "randomx-ghostrider",
    checks: [
      {
        expected: "84402e62b6bedafcd65f6ba13b59ff19ad7f273900c59fa49bfbb5f67e10030f",
        actual: () =>
          multiHashing
            .cryptonight(
              Buffer.from(
                "000000208c246d0b90c3b389c4086e8b672ee040d64db5b9648527133e217fbfa48da64c0f3c0a0b0e8350800568b40fbb323ac3ccdf2965de51b9aaeb939b4f11ff81c49b74a16156ff251c00000000",
                "hex"
              ),
              18
            )
            .toString("hex"),
      },
      {
        expected: "true",
        actual: () => {
          try {
            multiHashing.cryptonight(Buffer.alloc(35), 18);
            return "false";
          } catch {
            return "true";
          }
        },
      },
    ],
  }),
  checkCase({
    id: "autolykos2",
    name: "autolykos2",
    checks: [
      {
        expected: "10cf53f111fa6236ab59d87a70888fca6bd4d8a9dec816df013b94b91f8e09d8",
        actual: () => {
          const msg = Buffer.from(
            "9dbb7796a8c29559d5906331975dae9e16f8513ee4864692dcee05fd12c09e6d",
            "hex"
          );
          const extraNonce1 = Buffer.from("9618", "hex");
          const extraNonce2 = Buffer.from("33e73592d373", "hex");
          const result = multiHashing.autolykos2_hashes(
            Buffer.concat([msg, extraNonce1, extraNonce2]),
            535357
          );

          return result[0].toString("hex");
        },
      },
    ],
  }),
  checkCase({
    id: "ethash",
    name: "ethash",
    checks: [
      {
        expected: "0000000000095d18875acd4a2c2a5ff476c9acf283b4975d7af8d6c33d119c74",
        actual: () =>
          toHex(
            multiHashing.ethash(
              Buffer.from(
                "f5afa3074287b2b33e975468ae613e023e478112530bc19d4187693c13943445",
                "hex"
              ),
              Buffer.from("ff4136b6b6a244ec", "hex"),
              1257006
            )[0]
          ),
      },
      {
        expected: "47da5e47804594550791c24331163c1f1fde5bc622170e83515843b2b13dbe14",
        actual: () =>
          toHex(
            multiHashing.ethash(
              Buffer.from(
                "f5afa3074287b2b33e975468ae613e023e478112530bc19d4187693c13943445",
                "hex"
              ),
              Buffer.from("ff4136b6b6a244ec", "hex"),
              1257006
            )[1]
          ),
      },
    ],
  }),
  checkCase({
    id: "etchash",
    name: "etchash",
    checks: [
      {
        expected: "0000000d4899e38dbd9ac5bdc3726e34669986f53af0c60f50c5aa54e7fa4ed0",
        actual: () =>
          toHex(
            multiHashing.etchash(
              Buffer.from(
                "053690289a0a9dac132c268d6ffe64ad8e025b74eefa61b51934c57d2a49d9e4",
                "hex"
              ),
              Buffer.from("fe09000002a784b0", "hex"),
              15658542
            )[0]
          ),
      },
      {
        expected: "9b4f5f7321d7b132ea2cc8d4eef5f61d906658cbf7bc49edd77c9a192c290697",
        actual: () =>
          toHex(
            multiHashing.etchash(
              Buffer.from(
                "053690289a0a9dac132c268d6ffe64ad8e025b74eefa61b51934c57d2a49d9e4",
                "hex"
              ),
              Buffer.from("fe09000002a784b0", "hex"),
              15658542
            )[1]
          ),
      },
    ],
  }),
  checkCase({
    id: "kawpow",
    name: "kawpow",
    checks: [
      {
        expected: "0000000718ba5143286c46f44eee668fdf59b8eba810df21e4e2f4ec9538fc20",
        actual: () =>
          multiHashing
            .kawpow(
              Buffer.from(
                "63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3",
                "hex"
              ),
              Buffer.from("88a23b0033eb959b", "hex"),
              Buffer.from(
                "89732e5ff8711c32558a308fc4b8ee77416038a70995670e3eb84cbdead2e337",
                "hex"
              )
            )
            .toString("hex"),
      },
      {
        expected: "true",
        actual: () => {
          const header = Buffer.from(
            "63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3",
            "hex"
          );
          const nonce = Buffer.from("88a23b0033eb959b", "hex");
          const [resultHash, mixHash] = multiHashing.kawpow_light(header, nonce, 0);
          const verifiedHash = multiHashing.kawpow(header, nonce, mixHash);

          return String(
            Buffer.isBuffer(resultHash) &&
              resultHash.length === 32 &&
              Buffer.isBuffer(mixHash) &&
              mixHash.length === 32 &&
              resultHash.equals(verifiedHash)
          );
        },
      },
      {
        expected: "true",
        actual: () => {
          const header = Buffer.alloc(32);
          const nonce = Buffer.alloc(8);
          const invalidCalls = [
            () => multiHashing.kawpow_light(Buffer.alloc(31), nonce, 0),
            () => multiHashing.kawpow_light(header, Buffer.alloc(7), 0),
            () => multiHashing.kawpow_light(header, nonce, -1),
            () => multiHashing.kawpow_light(header, nonce, 1.5),
          ];

          return String(
            invalidCalls.every((call) => {
              try {
                call();
                return false;
              } catch {
                return true;
              }
            })
          );
        },
      },
    ],
  }),
  checkCase({
    id: "astrobwt",
    name: "astrobwt",
    checks: [
      {
        expected: "7e8844f2d6b7a43498fe6d226527689023da8a52f9fc4ec69e5aaaa63edce1c1",
        actual: () => multiHashing.astrobwt(sharedAstroInput, 0).toString("hex"),
      },
    ],
  }),
  checkCase({
    id: "astrobwt-dero-he",
    name: "astrobwt-dero-he",
    checks: [
      {
        expected: "489ed2661427986503fb8725e1d398da27ee253db4378798bf5a5c94ee0ce22a",
        actual: () => multiHashing.astrobwt(sharedAstroInput, 1).toString("hex"),
      },
    ],
  }),
  vectorCase({
    id: "k12",
    name: "k12",
    file: "k12.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input, encoding }) =>
      multiHashing.k12(Buffer.from(input, encoding)).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-1",
    name: "cryptonight-1",
    file: "cryptonight-1.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 1).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-2",
    name: "cryptonight-2",
    file: "cryptonight-2.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 8).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-r",
    name: "cryptonight-r",
    file: "cryptonight-r.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      multiHashing.cryptonight(Buffer.from(input, "hex"), 13, 1806260).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-half",
    name: "cryptonight-half",
    file: "cryptonight-half.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 9).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-msr",
    name: "cryptonight-msr",
    file: "cryptonight-msr.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 4).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-xao",
    name: "cryptonight-xao",
    file: "cryptonight-xao.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 6).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-rto",
    name: "cryptonight-rto",
    file: "cryptonight-rto.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 7).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-wow",
    name: "cryptonight-wow",
    file: "cryptonight-wow.txt",
    parseLine: parseCnLineWithHeight,
    execute: ({ input, height }) =>
      multiHashing.cryptonight(Buffer.from(input, "hex"), 12, height).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-gpu",
    name: "cryptonight-gpu",
    file: "cryptonight-gpu.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 11).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-rwz",
    name: "cryptonight-rwz",
    file: "cryptonight-rwz.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 14).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-zls",
    name: "cryptonight-zls",
    file: "cryptonight-zls.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 15).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-ccx",
    name: "cryptonight-ccx",
    file: "cryptonight-ccx.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 17).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-double",
    name: "cryptonight-double",
    file: "cryptonight-double.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 16).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight",
    name: "cryptonight",
    file: "cryptonight.txt",
    parseLine: (line) => parseCnLine(line),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input)).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-light",
    name: "cryptonight-light",
    file: "cryptonight_light.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight_light(Buffer.from(input, "hex"), 0).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-light-1",
    name: "cryptonight-light-1",
    file: "cryptonight_light-1.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight_light(Buffer.from(input, "hex"), 1).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-heavy",
    name: "cryptonight-heavy",
    file: "cryptonight_heavy.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight_heavy(Buffer.from(input, "hex")).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-heavy-xhv",
    name: "cryptonight-heavy-xhv",
    file: "cryptonight_heavy-xhv.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      multiHashing.cryptonight_heavy(Buffer.from(input, "hex"), 1).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-heavy-tube",
    name: "cryptonight-heavy-tube",
    file: "cryptonight_heavy-tube.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      multiHashing.cryptonight_heavy(Buffer.from(input, "hex"), 2).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-pico",
    name: "cryptonight-pico",
    file: "cryptonight_pico.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight_pico(Buffer.from(input, "hex")).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "rx-0",
    name: "rx/0",
    file: "rx0.txt",
    parseLine: parseRandomXLine,
    execute: ({ input, seed }) => multiHashing.randomx(Buffer.from(input), Buffer.from(seed), 0).toString("hex"),
    formatActual: ({ seed, input }, actual) => `${seed} '${input}': ${actual}`,
  }),
  checkCase({
    id: "rx-2",
    name: "rx/2",
    checks: [
      {
        expected: "329a16176b038502ba70e2350e61809227f247dacab444591ea2c21a9745b0fa",
        actual: () =>
          multiHashing
            .randomx(Buffer.from("This is a test"), Buffer.from("12345678901234567890123456789012"), "rx/2")
            .toString("hex"),
      },
      {
        expected: "3debd156210ca7b1eefb2e22c657ec68fa7d9859466cc809213788d741b33a02",
        actual: () =>
          multiHashing
            .randomx(Buffer.from("00", "hex"), Buffer.from("12345678901234567890123456789012"), "rx/2")
            .toString("hex"),
      },
    ],
  }),
  vectorCase({
    id: "rx-xeq",
    name: "rx/xeq",
    file: "rx_xeq.txt",
    parseLine: parseRandomXLine,
    execute: ({ input, seed }) =>
      multiHashing.randomx(Buffer.from(input), Buffer.from(seed), 22).toString("hex"),
    formatActual: ({ seed, input }, actual) => `${seed} '${input}': ${actual}`,
  }),
  vectorCase({
    id: "rx-arq",
    name: "rx/arq",
    file: "rx_arq.txt",
    parseLine: parseRandomXLine,
    execute: ({ input, seed }) => multiHashing.randomx(Buffer.from(input), Buffer.from(seed), 2).toString("hex"),
    formatActual: ({ seed, input }, actual) => `${seed} '${input}': ${actual}`,
  }),
  checkCase({
    id: "rx-panther",
    name: "rx/panther",
    checks: [
      {
        expected: "8ef59b356386cccba1e481c79fe1bf4423b8837d539610842a4ab576695e0800",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from(
                "0c0cedabc4f8059535516f43f0f480ca4ab081ef4119fc8b1eb980e78f16cfad8fb3227f5f113e278400003e2d90c6f83a2f0f95f829455e739f8c16d5eeedad382804b2cfefea4b150e4c01",
                "hex"
              ),
              Buffer.from(
                "1b7d5a95878b2d38be374cf3476bd07f5ea83adf2e8ca3f34aca49009af7f498",
                "hex"
              ),
              3
            )
            .toString("hex"),
      },
    ],
  }),
  checkCase({
    id: "rx-switch",
    name: "rx/switch",
    checks: Array.from({ length: 2 }, () => [
      {
        expected: "2d4dc87b3d1d8edf238b4adc546439388f1e9a796066f519f2c0cb2e9fe6fcd2",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from("This is a test"),
              Buffer.from("12345678901234567890123456789012"),
              22
            )
            .toString("hex"),
      },
      {
        expected: "8ef59b356386cccba1e481c79fe1bf4423b8837d539610842a4ab576695e0800",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from(
                "0c0cedabc4f8059535516f43f0f480ca4ab081ef4119fc8b1eb980e78f16cfad8fb3227f5f113e278400003e2d90c6f83a2f0f95f829455e739f8c16d5eeedad382804b2cfefea4b150e4c01",
                "hex"
              ),
              Buffer.from(
                "1b7d5a95878b2d38be374cf3476bd07f5ea83adf2e8ca3f34aca49009af7f498",
                "hex"
              ),
              3
            )
            .toString("hex"),
      },
    ]).flat(),
  }),
  checkCase({
    id: "argon2-chukwa",
    name: "argon2-chukwa",
    checks: [
      {
        expected: "c158a105ae75c7561cfd029083a47a87653d51f914128e21c1971d8b10c49034",
        actual: () => multiHashing.argon2(sharedArgonInput, 0).toString("hex"),
      },
    ],
  }),
  checkCase({
    id: "argon2-chukwa2",
    name: "argon2-chukwa2",
    checks: [
      {
        expected: "77cf6958b3536e1f9f0d1ea165f22811ca7bc487ea9f52030b5050c17fcdd8f5",
        actual: () => multiHashing.argon2(sharedArgonInput, 2).toString("hex"),
      },
    ],
  }),
  checkCase({
    id: "argon2-wrkz",
    name: "argon2-wrkz",
    checks: [
      {
        expected: "35e083d4b9c64c2a68820a431f61311998a8cd1864dba4077e25b7f121d54bd1",
        actual: () => multiHashing.argon2(sharedArgonInput, 1).toString("hex"),
      },
    ],
  }),
];

const baseOptionalCases = [
  vectorCase({
    id: "cryptonight-xtl",
    name: "cryptonight-xtl",
    file: "cryptonight-xtl.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) => multiHashing.cryptonight(Buffer.from(input, "hex"), 3).toString("hex"),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  checkCase({
    id: "rx-defyx",
    name: "rx/defyx",
    checks: [
      {
        expected: "239c17fc48c27a4e7254cfb7be3f9ac69f0ec9c6eb55e20cc7696d64bee7a694",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from("This is a test"),
              Buffer.from(
                "1000000000000000000000000000000000000000000000000000000000000000",
                "hex"
              ),
              1
            )
            .toString("hex"),
      },
      {
        expected: "239c17fc48c27a4e7254cfb7be3f9ac69f0ec9c6eb55e20cc7696d64bee7a694",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from("This is a test"),
              Buffer.from(
                "1000000000000000000000000000000000000000000000000000000000000000",
                "hex"
              ),
              "defyx"
            )
            .toString("hex"),
      },
    ],
  }),
  checkCase({
    id: "rx-wow",
    name: "rx/wow",
    checks: [
      {
        expected: "7f7d2ec8dd966f1bacdb19f450255a46eef353d917758f775559df6f6431ce33",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from("This is a test"),
              Buffer.from(
                "0000000000000000000000000000000000000000000000000000000000000001",
                "hex"
              ),
              17
            )
            .toString("hex"),
      },
    ],
  }),
  checkCase({
    id: "rx-loki",
    name: "rx/loki",
    checks: [
      {
        expected: "3c1f6d871c8571ae74cce3c6ff7d11ed7f5848c19a26d9c5972869cfabc449a8",
        actual: () =>
          multiHashing
            .randomx(
              Buffer.from("This is a test"),
              Buffer.from(
                "000000000000000100000000000000000000000f000000042000000000000000",
                "hex"
              ),
              18
            )
            .toString("hex"),
      },
    ],
  }),
  vectorCase({
    id: "rx-keva",
    name: "rx/keva",
    file: "rx_keva.txt",
    parseLine: parseRandomXLine,
    execute: ({ input, seed }) =>
      multiHashing.randomx(Buffer.from(input), Buffer.from(seed), 19).toString("hex"),
    formatActual: ({ seed, input }, actual) => `${seed} '${input}': ${actual}`,
  }),
  vectorCase({
    id: "rx-graft",
    name: "rx/graft",
    file: "rx_graft.txt",
    parseLine: parseRandomXLine,
    execute: ({ input, seed }) =>
      multiHashing.randomx(Buffer.from(input), Buffer.from(seed), 20).toString("hex"),
    formatActual: ({ seed, input }, actual) => `${seed} '${input}': ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-async",
    name: "cryptonight-async",
    file: "cryptonight-1.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      new Promise((resolve, reject) => {
        const method = getMethod("cryptonight_async");
        method(Buffer.from(input, "hex"), 1, (error, result) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(result.toString("hex"));
        });
      }),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-wow-async",
    name: "cryptonight-wow-async",
    file: "cryptonight-wow.txt",
    parseLine: parseCnLineWithHeight,
    execute: ({ input, height }) =>
      new Promise((resolve, reject) => {
        const method = getMethod("cryptonight_async");
        method(Buffer.from(input, "hex"), 12, height, (error, result) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(result.toString("hex"));
        });
      }),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-heavy-async",
    name: "cryptonight-heavy-async",
    file: "cryptonight_heavy.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      new Promise((resolve, reject) => {
        const method = getMethod("cryptonight_heavy_async");
        method(Buffer.from(input, "hex"), (error, result) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(result.toString("hex"));
        });
      }),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-light-async",
    name: "cryptonight-light-async",
    file: "cryptonight_light-1.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      new Promise((resolve, reject) => {
        const method = getMethod("cryptonight_light_async");
        method(Buffer.from(input, "hex"), 1, (error, result) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(result.toString("hex"));
        });
      }),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-pico-async",
    name: "cryptonight-pico-async",
    file: "cryptonight_pico.txt",
    parseLine: (line) => parseCnLine(line, "hex"),
    execute: ({ input }) =>
      new Promise((resolve, reject) => {
        const method = getMethod("cryptonight_pico_async");
        method(Buffer.from(input, "hex"), (error, result) => {
          if (error) {
            reject(error);
            return;
          }

          resolve(result.toString("hex"));
        });
      }),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
  vectorCase({
    id: "cryptonight-sync-vs-async",
    name: "cryptonight-sync-vs-async",
    file: "cryptonight.txt",
    parseLine: (line) => parseCnLine(line),
    execute: ({ input }) =>
      new Promise((resolve, reject) => {
        const method = getMethod("cryptonight_async");
        method(Buffer.from(input), (error, asyncResult) => {
          if (error) {
            reject(error);
            return;
          }

          const syncResult = multiHashing.cryptonight(Buffer.from(input)).toString("hex");
          const asyncHex = asyncResult.toString("hex");

          if (asyncHex !== syncResult) {
            reject(new Error(`sync/async disagreement: ${asyncHex} vs ${syncResult}`));
            return;
          }

          resolve(asyncHex);
        });
      }),
    formatActual: ({ input }, actual) => `${input}: ${actual}`,
  }),
];

// MoneroOcean live support checked against https://api.moneroocean.stream/pool/stats
// on 2026-04-07. Unsupported algos stay available behind --all as legacy coverage.
const legacyCaseIds = new Set([
  "ethash",
  "astrobwt",
  "astrobwt-dero-he",
  "k12",
  "cryptonight-1",
  "cryptonight-2",
  "cryptonight-msr",
  "cryptonight-xao",
  "cryptonight-rto",
  "cryptonight-wow",
  "cryptonight-rwz",
  "cryptonight-zls",
  "cryptonight-ccx",
  "cryptonight-double",
  "cryptonight",
  "cryptonight-light",
  "cryptonight-light-1",
  "cryptonight-heavy",
  "argon2-chukwa",
  "argon2-wrkz",
  "cryptonight-heavy-tube",
]);

const activeCases = baseActiveCases.filter((entry) => !legacyCaseIds.has(entry.id));
const optionalCases = baseOptionalCases.concat(
  baseActiveCases.filter((entry) => legacyCaseIds.has(entry.id))
);
const allCases = activeCases.concat(optionalCases);

async function runRequestedCase(requestedCaseId, options = {}) {
  const { report = false } = options;
  const testCase = allCases.find((entry) => entry.id === requestedCaseId);
  if (!testCase) {
    throw new Error(`Unknown case: ${requestedCaseId}`);
  }

  await testCase.run();
  if (report) {
    console.log(`\u2714 ${testCase.name}`);
  }
}

function runDriver(includeOptional = false) {
  const cases = includeOptional ? allCases : activeCases;
  let failures = 0;

  for (const testCase of cases) {
    const result = spawnSync(process.execPath, [__filename, "--case", testCase.id, "--quiet"], {
      cwd: path.join(__dirname, ".."),
      stdio: "inherit",
    });

    if (result.status !== 0) {
      failures += 1;
    } else {
      console.log(`\u2714 ${testCase.name}`);
    }
  }

  if (!includeOptional && optionalCases.length > 0) {
    console.log(
      `Skipped ${optionalCases.length} legacy-only stability cases. Run 'node tests/stability.js --all' to include them.`
    );
  }

  if (failures > 0) {
    process.exit(1);
  }
}

function isNodeTestInvocation() {
  return (
    Boolean(process.env.NODE_TEST_CONTEXT) ||
    process.execArgv.includes("--test") ||
    process.execArgv.some((arg) => arg.startsWith("--test-"))
  );
}

function runCaseProcess(testCase) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [__filename, "--case", testCase.id, "--quiet"], {
      cwd: path.join(__dirname, ".."),
      env: { ...process.env, NODE_TEST_CONTEXT: "" },
      stdio: "inherit",
    });

    child.on("error", reject);
    child.on("exit", (status, signal) => {
      if (status === 0) {
        resolve();
        return;
      }

      reject(
        new Error(
          signal
            ? `Test case exited due to signal ${signal}`
            : `Test case exited with code ${status}`
        )
      );
    });
  });
}

function registerNodeTests() {
  const test = require("node:test");

  for (const testCase of activeCases) {
    test(testCase.name, () => runCaseProcess(testCase));
  }
}

module.exports = {
  activeCases,
  optionalCases,
  allCases,
  runRequestedCase,
  runDriver,
};

if (isNodeTestInvocation() && !process.argv.includes("--case")) {
  registerNodeTests();
} else if (require.main === module) {
  const includeOptional = process.argv.includes("--all");
  const quiet = process.argv.includes("--quiet");
  const caseIndex = process.argv.indexOf("--case");
  const requestedCaseId = caseIndex === -1 ? null : process.argv[caseIndex + 1];

  if (requestedCaseId) {
    runRequestedCase(requestedCaseId, { report: !quiet }).catch((error) => {
      console.error(error.message);
      process.exit(1);
    });
  } else {
    runDriver(includeOptional);
  }
}
