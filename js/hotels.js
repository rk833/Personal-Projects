document.addEventListener("DOMContentLoaded", () => {
  // Optimize animation performance
  const elements = document.querySelectorAll(".fade-target");
  
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          // Add small random delay for natural feel
          const delay = Math.random() * 150;
          requestAnimationFrame(() => {
            setTimeout(() => {
              entry.target.classList.add("fade-in-up");
              observer.unobserve(entry.target);
            }, delay);
          });
        }
      });
    },
    {
      threshold: 0.1,
      rootMargin: "20px",
    }
  );

  elements.forEach((el) => observer.observe(el));

  // Handle video loading
  const heroVideo = document.querySelector('.hero-video');
  if (heroVideo) {
    heroVideo.addEventListener('loadeddata', () => {
      heroVideo.play().catch(() => {
        // Fallback for autoplay policy
        const playButton = document.createElement('button');
        playButton.textContent = 'Play Video';
        playButton.classList.add('video-play-button');
        heroVideo.parentNode.appendChild(playButton);
        
        playButton.addEventListener('click', () => {
          heroVideo.play();
          playButton.remove();
        });
      });
    });
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