function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

const encoder = new TextEncoder("utf-8");
let keyPair, spki;

function message(port) {
  return function (e) {
    if (e.data === "spki") {
      port.postMessage({ spki: spki });
    } else if (e.data === "ping") {
      port.postMessage("pong");
    } else if (typeof e.data === "object") {
      self.crypto.subtle
        .sign(
          { name: "ECDSA", hash: { name: "SHA-384" } },
          keyPair.privateKey,
          encoder.encode(e.data.sign)
        )
        .then((signature) => {
          port.postMessage({
            sign: e.data.sign,
            digest: btoa(ab2str(signature)),
          });
        })
        .catch((err) => {
          port.postMessage({ error: err });
        });
    } else {
      port.postMessage({ error: e.data });
    }
  };
}

self.crypto.subtle
  .generateKey({ name: "ECDSA", namedCurve: "P-384" }, false, [
    "sign",
    "verify",
  ])
  .then((res) => {
    keyPair = res;

    self.crypto.subtle.exportKey("spki", keyPair.publicKey).then((res) => {
      spki = btoa(ab2str(res));
    });
  });

self.onmessage = function (e) {
  message(self)(e);
};

self.onconnect = function (e) {
  const port = e.ports[0];
  port.onmessage = message(port);
  port.start();
};
