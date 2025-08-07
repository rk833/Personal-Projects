document.addEventListener("DOMContentLoaded", () => {
  // Optimize animation performance
  const elements = document.querySelectorAll(".fade-target");
  
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          // Add small random delay for natural feel
          const delay = Math.random() * 200;
          setTimeout(() => {
            entry.target.classList.add("fade-in-up");
            observer.unobserve(entry.target);
          }, delay);
        }
      });
    },
    {
      threshold: 0.1,
      rootMargin: "20px",
    }
  );

  elements.forEach((el) => observer.observe(el));

  // Handle image loading
  const images = document.querySelectorAll('img');
  images.forEach(img => {
    img.addEventListener('load', () => {
      img.classList.add('loaded');
    });
    if (img.complete) {
      img.classList.add('loaded');
    }
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