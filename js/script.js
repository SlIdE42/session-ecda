(function () {
  "use strict";

  function getCookie(name) {
    const r = document.cookie.match("\\b" + name + "=([^;]*)\\b");
    return r ? r[1] : null;
  }

  function enable() {
    document.querySelectorAll("input[type=submit]").forEach(function (node) {
      node.removeAttribute("disabled");
    });
  }

  function sign(worker, data) {
    return new Promise(function (resolve, reject) {
      const id = setTimeout(function () {
        reject(new Error("timeout"));
      }, 5000);
      const listener = function (event) {
        if (typeof event.data === "object" && event.data.sign === data) {
          clearTimeout(id);
          worker.removeEventListener("message", listener);
          return resolve(event.data.digest);
        }
      };
      worker.addEventListener("message", listener);
      worker.postMessage({ sign: data });
    });
  }

  function spki(worker) {
    return new Promise(function (resolve, reject) {
      const id = setTimeout(function () {
        reject(new Error("timeout"));
      }, 5000);
      const listener = function (event) {
        if (typeof event.data === "object" && event.data.spki) {
          clearTimeout(id);
          worker.removeEventListener("message", listener);
          return resolve(event.data.spki);
        }
      };

      worker.addEventListener("message", listener);
      worker.postMessage("spki");
    });
  }

  function submitSPKI(event) {
    const node = event.target.querySelector("input[name=spki]");

    return new Promise(function (resolve, reject) {
      if (!node) {
        return resolve();
      }

      return spki(worker)
        .then(function (spki) {
          node.setAttribute("value", spki);
          return resolve();
        })
        .catch(function (err) {
          return reject(err);
        });
    });
  }

  function submitSignature(event) {
    const node = event.target.querySelector("input[name=sign]");

    return new Promise(function (resolve, reject) {
      if (!node) {
        return resolve();
      }

      const data = getCookie("challenge");
      return sign(worker, data)
        .then(function (signature) {
          node.setAttribute("value", signature);
          return resolve();
        })
        .catch(function (err) {
          return reject(err);
        });
    });
  }

  if (!("crypto" in window || !("subtle" in window.crypto))) {
    window.alert("SubtleCrypto not available!");
    return;
  }

  const options = { credentials: "include" };
  const worker = (function () {
    if ("SharedWorker" in window) {
      const worker = new SharedWorker("js/worker.js", options);
      worker.port.start();
      return worker.port;
    } else if ("Worker" in window) {
      return new Worker("js/worker.js", options);
    } else {
      return;
    }
  })();
  if (!worker) {
    window.alert("Web Workers not available!");
    return;
  }
  if (document.readyState === "loading") {
    window.addEventListener("DOMContentLoaded", enable);
  } else {
    enable();
  }

  // worker.addEventListener("message", function (e) {});

  // setInterval(() => {
  //   worker.postMessage("ping");
  // }, 1000);

  worker.addEventListener("messageerror", function (error) {
    window.alert(error);
    console.error(error);
  });

  window.addEventListener("click", function (event) {
    if (event.target.nodeName === "A") {
      event.preventDefault();
      const href = event.target.getAttribute("href");
      sign(worker, getCookie("challenge"))
        .then(function (signature) {
          fetch(href, {
            credentials: "include",
            redirect: "follow",
            headers: new Headers({ "X-XSRF-Token": signature }),
          })
            .then(function (response) {
              if (!response.ok) {
                throw new Error(response.statusText);
              }
              history.pushState({}, "", response.url);
              return response.text();
            })
            .then(function (text) {
              const html = new DOMParser().parseFromString(text, "text/html");
              document.body = html.body;
              document.title = html.title;
              enable();
            })
            .catch(function (err) {
              window.alert(err);
            });
        })
        .catch(function (err) {
          window.alert(err);
        });
    }
  });

  window.addEventListener("submit", function (event) {
    event.preventDefault();
    Promise.all([submitSPKI(event), submitSignature(event)])
      .then(function () {
        // event.target.submit();
        const method = event.target.getAttribute("method");
        const action = event.target.getAttribute("action");
        const formData = new FormData(event.target);
        fetch(action, {
          credentials: "include",
          method: method,
          body: formData,
          redirect: "follow",
        })
          .then(function (response) {
            if (!response.ok) {
              throw new Error(response.statusText);
            }
            history.pushState({}, "", response.url);
            return response.text();
          })
          .then(function (text) {
            const html = new DOMParser().parseFromString(text, "text/html");
            document.body = html.body;
            document.title = html.title;
            enable();
          })
          .catch(function (err) {
            window.alert(err);
          });
      })
      .catch(function (err) {
        window.alert(err);
        console.error(err);
      });
  });
})();
