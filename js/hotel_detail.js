document.addEventListener("DOMContentLoaded", () => {
    const checkInInput = document.querySelector('input[name="check_in"]');
    const checkOutInput = document.querySelector('input[name="check_out"]');

    checkInInput.addEventListener('change', function() {
        checkOutInput.min = this.value;
        const maxStay = new Date(this.value);
        maxStay.setDate(maxStay.getDate() + 30);
        checkOutInput.max = maxStay.toISOString().split('T')[0];
    });

    // Add fade animation
    const elements = document.querySelectorAll(".fade-target");
    
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry, index) => {
                if (entry.isIntersecting) {
                    setTimeout(() => {
                        entry.target.classList.add("fade-in-up");
                    }, index * 200); // 200ms delay between each element
                    observer.unobserve(entry.target);
                }
            });
        },
        {
            threshold: 0.1,
            rootMargin: "50px",
        }
    );

    elements.forEach((el) => observer.observe(el));
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