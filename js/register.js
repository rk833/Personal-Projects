document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector("form");
    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("confirm_password");

    form.addEventListener("submit", function (event) {
        if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }

        if (password.value !== confirmPassword.value) {
            confirmPassword.setCustomValidity("Passwords do not match");
            event.preventDefault();
        } else {
            confirmPassword.setCustomValidity("");
        }

        form.classList.add("was-validated");
    });

    // Clear custom validity when user types
    confirmPassword.addEventListener("input", function () {
        if (password.value === confirmPassword.value) {
            confirmPassword.setCustomValidity("");
        } else {
            confirmPassword.setCustomValidity("Passwords do not match");
        }
    });

    // Toggle password visibility
    document.getElementById("togglePassword").addEventListener("click", function () {
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

    // Toggle confirm password visibility
    document.getElementById("toggleConfirmPassword").addEventListener("click", function () {
        const confirmPassword = document.getElementById("confirm_password");
        const icon = this.querySelector("i");

        if (confirmPassword.type === "password") {
            confirmPassword.type = "text";
            icon.classList.remove("fa-eye");
            icon.classList.add("fa-eye-slash");
        } else {
            confirmPassword.type = "password";
            icon.classList.remove("fa-eye-slash");
            icon.classList.add("fa-eye");
        }
    });

    // Form Validation
    document.getElementById("registerForm").addEventListener("submit", function (e) {
        e.preventDefault();

        // Input values
        const name = document.getElementById("name").value.trim();
        const email = document.getElementById("email").value.trim();
        const contact = document.getElementById("contact").value.trim();
        const city = document.getElementById("city").value;
        const password = document.getElementById("password").value;
        const confirmPassword = document.getElementById("confirmPassword").value;
        const termsChecked = document.getElementById("terms").checked;

        // Form Validation
        if (!name || !email || !contact || !city || !password || !confirmPassword) {
            alert("Please fill out all fields.");
            return;
        }

        if (!/^[a-zA-Z ]+$/.test(name)) {
            alert("Name can only contain letters and spaces.");
            return;
        }

        if (!/^\d{10}$/.test(contact)) {
            alert("Contact number must be 10 digits.");
            return;
        }

        if (password.length < 6) {
            alert("Password must be at least 6 characters.");
            return;
        }

        if (password !== confirmPassword) {
            alert("Passwords do not match.");
            return;
        }

        if (!termsChecked) {
            alert("You must agree to the terms and conditions.");
            return;
        }

        // Simulate registration success
        alert("Registration Successful!");
        window.location.href = "login.html";
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