// Small enhancements on top of pages that work without JavaScript.
// Loaded as a file because the Content-Security-Policy forbids inline scripts.

var root = document.documentElement;

// Copy buttons (`ui::copy_button`): only shown when the clipboard is usable.
if (navigator.clipboard && window.isSecureContext) {
  root.classList.add("js-copy");
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

// Dialogs (`ui::modal`). Buttons open and close them with invoker commands (`commandfor`);
// this does it in browsers that don't have those yet.
if (!("command" in HTMLButtonElement.prototype)) {
  document.addEventListener("click", function (event) {
    var button = event.target.closest("button[commandfor]");
    var dialog = button && document.getElementById(button.getAttribute("commandfor"));
    if (!dialog || !dialog.showModal) return;
    var command = button.getAttribute("command");
    if (command === "show-modal") dialog.showModal();
    if (command === "close") dialog.close();
  });
}

// A click on the backdrop closes a dialog (`closedby="any"`), where browsers don't do it.
if (window.HTMLDialogElement && !("closedBy" in HTMLDialogElement.prototype)) {
  document.addEventListener("click", function (event) {
    var dialog = event.target;
    if (dialog.tagName === "DIALOG" && dialog.open && dialog.getAttribute("closedby") === "any") {
      dialog.close();
    }
  });
}

// Irreversible forms (`form[data-confirm]`, see `ui::confirm`) ask in the confirmation dialog
// instead of needing their tick box ticked. Without dialogs, the tick box stays.
if (window.HTMLDialogElement) {
  root.classList.add("js");

  var unrequire = function (element) {
    element.querySelectorAll("form[data-confirm] .confirm-box input").forEach(function (box) {
      box.required = false;
    });
  };
  unrequire(document);
  document.addEventListener("htmx:load", function (event) {
    unrequire(event.target);
  });

  var pending = null;
  // Capture, so the dialog comes before htmx sends the form.
  document.addEventListener(
    "submit",
    function (event) {
      var form = event.target;
      var dialog = document.getElementById("confirm-dialog");
      if (!form.matches("form[data-confirm]") || form.dataset.confirmed || !dialog) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      var submitter = event.submitter;
      var label = submitter ? (submitter.querySelector(".btn-label") || submitter).textContent.trim() : "Continue";
      dialog.querySelector("[data-confirm-title]").textContent = label + "?";
      dialog.querySelector("[data-confirm-text]").textContent = form.dataset.confirm;
      dialog.querySelector("[data-confirm-ok]").textContent = label;
      pending = { form: form, submitter: submitter };
      dialog.showModal();
    },
    true,
  );

  document.addEventListener("click", function (event) {
    if (!event.target.closest("[data-confirm-ok]") || !pending) return;
    var form = pending.form;
    var submitter = pending.submitter;
    pending = null;
    document.getElementById("confirm-dialog").close();
    var box = form.querySelector(".confirm-box input");
    if (box) box.checked = true;
    form.dataset.confirmed = "yes";
    form.requestSubmit(submitter || undefined);
    delete form.dataset.confirmed;
  });
}

// Toasts (`ui::toast`): the close button.
document.addEventListener("click", function (event) {
  var close = event.target.closest(".toast-close");
  if (close) close.closest(".toast").classList.add("closed");
});

// Slow actions: tell screen readers the form is busy while htmx sends it. The spinner is CSS.
document.addEventListener("htmx:beforeRequest", function (event) {
  if (event.target.tagName === "FORM") event.target.setAttribute("aria-busy", "true");
});
document.addEventListener("htmx:afterRequest", function (event) {
  if (event.target.tagName === "FORM") event.target.removeAttribute("aria-busy");
});
