var forge = require('../..');

console.log('Times in 1000s of bytes/sec processed.');

// Allow user-defined parameters
var dataSize = 1024; // Default data size in bytes
var duration = 5; // Default duration in seconds

// Get user input for data size and duration if needed
process.argv.forEach((val, index) => {
  if (index === 2) {
    dataSize = parseInt(val) || dataSize;
  }
  if (index === 3) {
    duration = parseInt(val) || duration;
  }
});

console.log(`Testing with ${dataSize} bytes of data for ${duration} seconds...`);

var algorithms = ['AES-CBC', 'AES-CFB', 'AES-OFB', 'AES-CTR', 'AES-GCM'];
var keySizes = [16, 24, 32]; // AES-128, AES-192, AES-256

// Run benchmarks for each algorithm and key size
algorithms.forEach(algorithm => {
  keySizes.forEach(keySize => {
    aes_128(algorithm, keySize);
  });
});

function aes_128(algorithm, keySize) {
  console.log(`Running ${algorithm} with ${keySize * 8}-bit key for ${duration} seconds...`);

  var key = forge.random.getBytesSync(keySize);
  var iv = forge.random.getBytes(algorithm === 'AES-GCM' ? 12 : 16);
  var plain = forge.random.getBytesSync(dataSize);

  // run for the specified duration
  var start = new Date().getTime();
  var passed = 0;
  var totalEncrypt = 0;
  var totalDecrypt = 0;
  var count = 0;

  while (passed < duration * 1000) {
    var input = forge.util.createBuffer(plain);

    // Encrypt and measure time
    var cipher = forge.cipher.createCipher(algorithm, key);
    cipher.start({ iv: iv });
    var now = new Date().getTime();
    cipher.update(input);
    if (!cipher.finish()) {
      console.error('Encryption error.');
      return;
    }
    totalEncrypt += new Date().getTime() - now;

    var ciphertext = cipher.output;
    var tag = cipher.mode.tag;
    count += cipher.output.length();

    // Decrypt and measure time
    cipher = forge.cipher.createDecipher(algorithm, key);
    cipher.start({ iv: iv, tag: tag });
    now = new Date().getTime();
    cipher.update(ciphertext);
    if (!cipher.finish()) {
      console.error('Decryption error.');
      return;
    }
    totalDecrypt += new Date().getTime() - now;

    passed = new Date().getTime() - start;

    // Optional: Display a simple progress bar
    process.stdout.write(`\rTime elapsed: ${(passed / 1000).toFixed(1)}s`);
  }

  // Final performance metrics
  var countKbps = (count / 1000);
  totalEncrypt /= 1000;
  totalDecrypt /= 1000;
  console.log(`\nAlgorithm: ${algorithm}, Key Size: ${keySize * 8}-bit`);
  console.log(`Encrypt: ${(countKbps / totalEncrypt).toFixed(2)} k/sec`);
  console.log(`Decrypt: ${(countKbps / totalDecrypt).toFixed(2)} k/sec`);
  console.log();
}
