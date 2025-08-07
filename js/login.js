document.addEventListener('DOMContentLoaded', function () {
  const loginForm = document.querySelector('form[action*="login"]');

  if (loginForm) {
      loginForm.addEventListener('submit', function (e) {
          const emailInput = loginForm.querySelector('input[name="email"]');
          const passwordInput = loginForm.querySelector('input[name="password"]');
          let isValid = true;

          // Validate email
          if (!emailInput.value.trim()) {
              isValid = false;
              alert('Please enter your email address.');
          } else if (!validateEmail(emailInput.value.trim())) {
              isValid = false;
              alert('Please enter a valid email address.');
          }

          // Validate password
          if (!passwordInput.value.trim()) {
              isValid = false;
              alert('Please enter your password.');
          }

          // Prevent form submission if validation fails
          if (!isValid) {
              e.preventDefault();
          }
      });
  }

  // Email validation function
  function validateEmail(email) {
      const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return regex.test(email);
  }
});



document.getElementById("togglePassword")
.addEventListener("click", function () {
  const password = document.getElementById("password");
  const icon = this.querySelector("i");

  if (password.type === "password") {
    password.type = "text";
    icon.classList.remove("fa-eye");
    icon.classList.add("fa-eye-slash");
  } else {
    password.type = "password";
    icon.classList.remove("fa-eye-slash");
    icon.classList.add("fa-eye");
  }
});

$(document).ready(function() {
  $('#login-form').on('submit', function(event) {
      event.preventDefault();
      var formData = $(this).serialize();
      
      $.ajax({
          type: 'POST',
          url: '{{ url_for("login") }}',
          data: formData,
          success: function(response) {
              if (response.success) {
                  window.location.href = response.redirect_url;
              } else {
                  $('#error-message').text(response.message).show();
              }
          },
          error: function() {
              $('#error-message').text('An error occurred. Please try again.').show();
          }
      });
  });
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