document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (event) {
    if (!window.confirm(form.dataset.confirm || "Are you sure?")) {
      event.preventDefault();
    }
  });
});
