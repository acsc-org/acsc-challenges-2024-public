document
  .getElementById("verify2FAForm")
  .addEventListener("submit", function (event) {
    event.preventDefault();
    const code = document.getElementById("code").value;
    const trustDevice = document.getElementById("trustDevice").checked;
    const captcha = document.getElementById("captchaInput").value;

    fetch("/verify-2fa", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        token: code,
        trustDevice: trustDevice,
        captcha: captcha,
      }),
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
          throw new Error("Verification failed");
        }
      })
      .catch((error) => {
        console.error("Error:", error);
      });
  });

window.onload = function () {
  fetch("/captcha")
    .then((response) => response.text())
    .then((data) => {
      document.getElementById("captcha-container").innerHTML = data;
    })
    .catch((error) => console.error("Error loading the CAPTCHA", error));
};
