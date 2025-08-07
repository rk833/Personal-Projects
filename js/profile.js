document
.querySelector('form[action*="change_password"]')
.addEventListener("submit", function (e) {
  const newPassword = this.querySelector(
    'input[name="new_password"]'
  ).value;
  const confirmPassword = this.querySelector(
    'input[name="confirm_password"]'
  ).value;

  if (newPassword !== confirmPassword) {
    e.preventDefault();
    alert("New passwords do not match!");
  }
});

    // Back to Top Button
    const backToTopButton = document.getElementById("back-to-top");
    if (backToTopButton) {
        window.addEventListener("scroll", () => {
            backToTopButton.style.display = window.scrollY > 300 ? "flex" : "none";
        });

        backToTopButton.addEventListener("click", () => {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }