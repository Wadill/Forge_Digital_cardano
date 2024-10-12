/**
 * Secure Hash Algorithm with 256-bit digest (SHA-256) implementation.
 *
 * See FIPS 180-2 for details.
 */

const forge = require('./forge');
require('./md');
require('./util');

const sha256 = module.exports = forge.sha256 = forge.sha256 || {};
forge.md.sha256 = forge.md.algorithms.sha256 = sha256;

// Constants
const BLOCK_SIZE = 64;
const DIGEST_LENGTH = 32;
const MESSAGE_LENGTH_SIZE = 8;

// Initial padding bytes and constant table
let _padding = null;
let _k = null;
let _initialized = false;

/**
 * Creates a SHA-256 message digest object.
 *
 * @return {Object} A message digest object.
 */
sha256.create = function() {
  // Initialize tables if needed
  if (!_initialized) {
    _init();
  }

  // SHA-256 state contains eight 32-bit integers
  let _state = null;
  let _input = forge.util.createBuffer();
  const _w = new Array(64);

  const md = {
    algorithm: 'sha256',
    blockLength: BLOCK_SIZE,
    digestLength: DIGEST_LENGTH,
    messageLength: 0, // 56-bit length of message so far
    fullMessageLength: Array(MESSAGE_LENGTH_SIZE / 4).fill(0),
  };

  /**
   * Starts the digest.
   *
   * @return {Object} This digest object.
   */
  md.start = function() {
    md.messageLength = 0;
    md.fullMessageLength.fill(0);
    _input = forge.util.createBuffer();
    _state = _initState();
    return md;
  };

  md.start(); // Automatically start digest on creation

  /**
   * Updates the digest with the given message input.
   *
   * @param {String|Buffer} msg The message input to update with.
   * @param {String} [encoding='raw'] The encoding to use (default: 'raw', other: 'utf8').
   * @return {Object} This digest object.
   */
  md.update = function(msg, encoding = 'raw') {
    if (encoding === 'utf8') {
      msg = forge.util.encodeUtf8(msg);
    }

    // Update message length
    let len = msg.length;
    md.messageLength += len;

    len = [(len / 0x100000000) >>> 0, len >>> 0];
    _updateMessageLength(md.fullMessageLength, len);

    _input.putBytes(msg);
    _processInputBuffer(_state, _w, _input);

    if (_input.read > 2048 || _input.length() === 0) {
      _input.compact();
    }

    return md;
  };

  /**
   * Produces the digest.
   *
   * @return {Object} A byte buffer containing the digest value.
   */
  md.digest = function() {
    const finalBlock = _prepareFinalBlock(_input, md);
    const finalState = Object.assign({}, _state);
    _update(finalState, _w, finalBlock);

    return _createDigestBuffer(finalState);
  };

  return md;
};

/**
 * Initializes the constant tables and padding.
 */
function _init() {
  _padding = String.fromCharCode(128) + forge.util.fillString(String.fromCharCode(0x00), 63);

  _k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  _initialized = true;
}

/**
 * Initializes the SHA-256 state.
 *
 * @return {Object} The initial state object.
 */
function _initState() {
  return {
    h0: 0x6A09E667, h1: 0xBB67AE85, h2: 0x3C6EF372, h3: 0xA54FF53A,
    h4: 0x510E527F, h5: 0x9B05688C, h6: 0x1F83D9AB, h7: 0x5BE0CD19,
  };
}

/**
 * Updates the full message length with the new length.
 *
 * @param {Array} fullMessageLength The current full message length.
 * @param {Array} len The new length to add.
 */
function _updateMessageLength(fullMessageLength, len) {
  for (let i = fullMessageLength.length - 1; i >= 0; --i) {
    fullMessageLength[i] += len[1];
    len[1] = len[0] + ((fullMessageLength[i] / 0x100000000) >>> 0);
    fullMessageLength[i] = fullMessageLength[i] >>> 0;
    len[0] = (len[1] / 0x100000000) >>> 0;
  }
}

/**
 * Prepares the final block for the digest computation.
 *
 * @param {Buffer} input The input buffer.
 * @param {Object} md The message digest object.
 * @return {Buffer} The final block buffer.
 */
function _prepareFinalBlock(input, md) {
  const finalBlock = forge.util.createBuffer();
  finalBlock.putBytes(input.bytes());

  const remaining = md.fullMessageLength[md.fullMessageLength.length - 1] + MESSAGE_LENGTH_SIZE;
  const overflow = remaining & (md.blockLength - 1);

  finalBlock.putBytes(_padding.substr(0, md.blockLength - overflow));

  let bits = md.fullMessageLength[0] * 8;
  for (let i = 0; i < md.fullMessageLength.length - 1; ++i) {
    const next = md.fullMessageLength[i + 1] * 8;
    bits += (next / 0x100000000) >>> 0;
    finalBlock.putInt32(bits >>> 0);
    bits = next >>> 0;
  }
  finalBlock.putInt32(bits);

  return finalBlock;
}

/**
 * Processes a chunk of input.
 *
 * @param {Object} s The SHA-256 state.
 * @param {Array} w The working array.
 * @param {Buffer} input The input buffer.
 */
function _processInputBuffer(s, w, input) {
  while (input.length() >= BLOCK_SIZE) {
    for (let i = 0; i < 16; ++i) {
      w[i] = input.getInt32();
    }
    for (let i = 16; i < 64; ++i) {
      const s0 = _rightRotate(w[i - 15], 7) ^ _rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = _rightRotate(w[i - 2], 17) ^ _rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    _update(s, w, input);
  }
}

/**
 * Updates the SHA-256 state with a chunk.
 *
 * @param {Object} s The SHA-256 state.
 * @param {Array} w The working array.
 * @param {Buffer} chunk The chunk to process.
 */
function _update(s, w, chunk) {
  // Compression function
  let a = s.h0, b = s.h1, c = s.h2, d = s.h3;
  let e = s.h4, f = s.h5, g = s.h6, h = s.h7;

  for (let i = 0; i < 64; ++i) {
    const s1 = _rightRotate(e, 6) ^ _rightRotate(e, 11) ^ _rightRotate(e, 25);
    const ch = (e & f) ^ (~e & g);
    const temp1 = (h + s1 + ch + _k[i] + w[i]) >>> 0;
    const s0 = _rightRotate(a, 2) ^ _rightRotate(a, 13) ^ _rightRotate(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (s0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  s.h0 = (s.h0 + a) >>> 0;
  s.h1 = (s.h1 + b) >>> 0;
  s.h2 = (s.h2 + c) >>> 0;
  s.h3 = (s.h3 + d) >>> 0;
  s.h4 = (s.h4 + e) >>> 0;
  s.h5 = (s.h5 + f) >>> 0;
  s.h6 = (s.h6 + g) >>> 0;
  s.h7 = (s.h7 + h) >>> 0;
}

/**
 * Creates a buffer containing the digest value from the state.
 *
 * @param {Object} s The SHA-256 state.
 * @return {Buffer} The digest buffer.
 */
function _createDigestBuffer(s) {
  const buffer = forge.util.createBuffer();
  buffer.putInt32(s.h0);
  buffer.putInt32(s.h1);
  buffer.putInt32(s.h2);
  buffer.putInt32(s.h3);
  buffer.putInt32(s.h4);
  buffer.putInt32(s.h5);
  buffer.putInt32(s.h6);
  buffer.putInt32(s.h7);
  return buffer;
}

/**
 * Performs a right rotation on a 32-bit value.
 *
 * @param {Number} x The value to rotate.
 * @param {Number} n The number of bits to rotate.
 * @return {Number} The rotated value.
 */
function _rightRotate(x, n) {
  return (x >>> n) | (x << (32 - n));
}
