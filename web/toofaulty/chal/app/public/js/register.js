document
  .getElementById("registerForm")
  .addEventListener("submit", function (e) {
    e.preventDefault();

    const formData = {
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
    };

    fetch("/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(formData),
    })
      .then((response) => {
        if (response.redirected) {
          window.location.href = response.url;
        } else {
          console.log("Registration failed");
        }
      })
      .catch((error) => console.error("Error:", error));
  });
