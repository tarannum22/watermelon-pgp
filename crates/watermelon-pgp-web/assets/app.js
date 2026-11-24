// Small enhancements on top of pages that work without JavaScript.
// Loaded as a file because the Content-Security-Policy forbids inline scripts.

// Copy buttons (`ui::copy_button`): only shown when the clipboard is usable.
if (navigator.clipboard && window.isSecureContext) {
  document.documentElement.classList.add("js-copy");
}

document.addEventListener("click", function (event) {
  var button = event.target.closest("button.copy");
  if (!button) return;
  event.preventDefault();
  navigator.clipboard.writeText(button.dataset.copy || "").then(function () {
    button.classList.add("copied");
    var label = button.getAttribute("aria-label");
    button.setAttribute("aria-label", "Copied");
    setTimeout(function () {
      button.classList.remove("copied");
      button.setAttribute("aria-label", label);
    }, 1500);
  });
});
