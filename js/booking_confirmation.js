document.addEventListener('DOMContentLoaded', function() {
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

    // Success icon animation
    const successIcon = document.querySelector('.fa-check-circle');
    if (successIcon) {
        successIcon.style.opacity = '0';
        setTimeout(() => {
            successIcon.style.opacity = '1';
            successIcon.classList.add('animate__animated', 'animate__bounceIn');
        }, 500);
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