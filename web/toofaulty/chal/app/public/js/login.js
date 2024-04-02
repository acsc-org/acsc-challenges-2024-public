document
  .getElementById("loginForm")
  .addEventListener("submit", function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const browser = bowser.getParser(window.navigator.userAgent);
    const browserObject = browser.getBrowser();
    const versionReg = browserObject.version.match(/^(\d+\.\d+)/);
    const version = versionReg ? versionReg[1] : "unknown";
    const deviceId = CryptoJS.HmacSHA1(
      `${browserObject.name} ${version}`,
      "2846547907"
    );

    fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Device-Id": deviceId,
      },
      body: JSON.stringify({ username, password }),
    })
      .then((response) => {
        if (response.redirected) {
          window.location.href = response.url;
        } else if (response.ok) {
          response.json().then((data) => {
            if (data.redirect) {
              window.location.href = data.redirect;
            } else {
              window.location.href = "/";
            }
          });
        } else {
          throw new Error("Login failed");
        }
      })
      .catch((error) => {
        console.error("Error:", error);
      });
  });

function redirectToRegister() {
  window.location.href = "/register";
}
