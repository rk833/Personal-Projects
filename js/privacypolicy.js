// Smooth scrolling for internal links (anchor links)
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();

        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

// Collapsible FAQ section (for example, to hide/show answers)
document.querySelectorAll('.faq-question').forEach(item => {
    item.addEventListener('click', function () {
        const answer = this.nextElementSibling; 
        answer.classList.toggle('show'); 
    });
});

document.addEventListener("DOMContentLoaded", () => {
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