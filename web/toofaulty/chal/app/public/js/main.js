function checkForErrorAndDisplayToast() {
  const urlParams = new URLSearchParams(window.location.search);
  const error = urlParams.get("error");

  if (error) {
    const toaster = document.getElementById("toaster");
    toaster.innerText = decodeURIComponent(error.replace(/\+/g, " "));
    toaster.style.display = "block";

    setTimeout(() => {
      toaster.style.display = "none";
    }, 4000);
  }
}

document.addEventListener("DOMContentLoaded", checkForErrorAndDisplayToast);
