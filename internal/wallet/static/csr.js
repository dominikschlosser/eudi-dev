// Creates a P-256 key and a PKCS #10 request in the browser, so the key never
// reaches the registrar. The subject stays empty because the registrar fills
// it from the registration.
window.eudiCreateKeyAndCSR = (() => {
  function derLength(n) {
    if (n < 0x80) return [n];
    const bytes = [];
    for (; n > 0; n >>= 8) bytes.unshift(n & 0xff);
    return [0x80 | bytes.length].concat(bytes);
  }
  function der(tag, content) {
    return [tag].concat(derLength(content.length), Array.from(content));
  }
  function derInteger(bytes) {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    const value = Array.from(bytes.slice(i));
    return der(0x02, value[0] & 0x80 ? [0].concat(value) : value);
  }
  function toPEM(label, bytes) {
    const b64 = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(bytes))));
    return '-----BEGIN ' + label + '-----\n' + b64.match(/.{1,64}/g).join('\n') + '\n-----END ' + label + '-----\n';
  }
  return async function createKeyAndCSR() {
    // Web Crypto exists only in a secure context.
    if (!crypto.subtle) throw new Error('This browser creates a key only on HTTPS or localhost. Paste a CSR instead.');
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey));
    const info = der(0x30, [].concat(der(0x02, [0]), der(0x30, []), Array.from(spki), der(0xa0, [])));
    // WebCrypto returns r and s concatenated. X.509 wants an ECDSA-Sig-Value.
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new Uint8Array(info)));
    const signature = der(0x30, derInteger(raw.slice(0, 32)).concat(derInteger(raw.slice(32))));
    const ecdsaWithSHA256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const csr = der(0x30, [].concat(info, der(0x30, ecdsaWithSHA256), der(0x03, [0].concat(signature))));
    return {
      key: toPEM('PRIVATE KEY', await crypto.subtle.exportKey('pkcs8', keys.privateKey)),
      csr: toPEM('CERTIFICATE REQUEST', new Uint8Array(csr)),
    };
  };
})();
