document.addEventListener('DOMContentLoaded', () => {
    const slider = document.getElementById('destinationSlider');
    let isDown = false;
    let startX;
    let currentTranslate = 0;
    let prevTranslate = 0;
    let animationID;
    let currentIndex = 0;
    let slideWidth;
    let slidesCount;
    let isScrolling = false;
    let scrollTimeout;

    // Initialize slider dimensions
    function init() {
        slideWidth = slider.querySelector('.slide').offsetWidth + 40; // Include margins
        slidesCount = slider.querySelectorAll('.slide').length;
        setPositionByIndex();
    }

    // Set slider position
    function setSliderPosition(position) {
        slider.style.transform = `translateX(${position}px)`;
    }

    function setPositionByIndex() {
        currentTranslate = currentIndex * -slideWidth;
        prevTranslate = currentTranslate;
        setSliderPosition(currentTranslate);
    }

    function animation() {
        setSliderPosition(currentTranslate);
        if (isDown) requestAnimationFrame(animation);
    }

    // Wheel event handler
    function handleWheel(e) {
        e.preventDefault();
        
        // Clear the previous timeout
        clearTimeout(scrollTimeout);
        
        // Set a flag to indicate scrolling
        isScrolling = true;
        
        // Determine scroll direction
        if (e.deltaY > 0 && currentIndex < slidesCount - 2) {
            currentIndex += 1;
        } else if (e.deltaY < 0 && currentIndex > 0) {
            currentIndex -= 1;
        }

        // Smooth transition
        slider.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
        setPositionByIndex();

        // Reset scrolling flag after animation
        scrollTimeout = setTimeout(() => {
            isScrolling = false;
        }, 500);
    }

    // Touch Events
    slider.addEventListener('touchstart', (e) => {
        if (isScrolling) return;
        isDown = true;
        slider.style.cursor = 'grabbing';
        startX = e.touches[0].clientX - currentTranslate;
        slider.style.transition = 'none';
        cancelAnimationFrame(animationID);
        
        animationID = requestAnimationFrame(animation);
    });

    slider.addEventListener('touchmove', (e) => {
        if (!isDown || isScrolling) return;
        e.preventDefault();
        const currentPosition = e.touches[0].clientX;
        currentTranslate = currentPosition - startX;
        
        // Add resistance at the edges
        if (currentTranslate > 0) {
            currentTranslate = currentTranslate * 0.3;
        } else if (currentTranslate < -(slidesCount - 2.5) * slideWidth) {
            const overflow = currentTranslate + (slidesCount - 2.5) * slideWidth;
            currentTranslate = -(slidesCount - 2.5) * slideWidth + overflow * 0.3;
        }
    });

    slider.addEventListener('touchend', touchEnd);
    slider.addEventListener('touchcancel', touchEnd);

    // Mouse Events
    slider.addEventListener('mousedown', (e) => {
        if (isScrolling) return;
        isDown = true;
        slider.style.cursor = 'grabbing';
        startX = e.clientX - currentTranslate;
        slider.style.transition = 'none';
        cancelAnimationFrame(animationID);
        
        animationID = requestAnimationFrame(animation);
    });

    slider.addEventListener('mousemove', (e) => {
        if (!isDown || isScrolling) return;
        e.preventDefault();
        const currentPosition = e.clientX;
        currentTranslate = currentPosition - startX;
        
        // Add resistance at the edges
        if (currentTranslate > 0) {
            currentTranslate = currentTranslate * 0.3;
        } else if (currentTranslate < -(slidesCount - 2.5) * slideWidth) {
            const overflow = currentTranslate + (slidesCount - 2.5) * slideWidth;
            currentTranslate = -(slidesCount - 2.5) * slideWidth + overflow * 0.3;
        }
    });

    slider.addEventListener('mouseup', touchEnd);
    slider.addEventListener('mouseleave', touchEnd);

    function touchEnd() {
        if (isScrolling) return;
        isDown = false;
        slider.style.cursor = 'grab';
        cancelAnimationFrame(animationID);

        const movedBy = currentTranslate - prevTranslate;
        
        // If moved enough negative -> next slide
        if (movedBy < -100 && currentIndex < slidesCount - 2) {
            currentIndex += 1;
        }
        
        // If moved enough positive -> prev slide
        if (movedBy > 100 && currentIndex > 0) {
            currentIndex -= 1;
        }

        slider.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
        setPositionByIndex();
    }

    // Add wheel event listener
    slider.addEventListener('wheel', handleWheel, { passive: false });

    // Prevent context menu on long press
    slider.addEventListener('contextmenu', e => {
        e.preventDefault();
        e.stopPropagation();
    });

    // Handle window resize
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            init();
        }, 250);
    });

    // Initialize slider
    init();

    // Image loading
    const images = document.querySelectorAll('.slide__image img');
    images.forEach(img => {
        img.addEventListener('load', () => {
            img.classList.add('loaded');
        });
    });

    // Prevent default touch behaviors
    document.addEventListener('touchmove', (e) => {
        if (e.target.closest('.slider')) {
            e.preventDefault();
        }
    }, { passive: false });

    // Add touch feedback
    const touchElements = document.querySelectorAll('.btn-subscribe, .experience, .slide__link');
    touchElements.forEach(element => {
        element.addEventListener('touchstart', () => {
            element.style.opacity = '0.7';
        });
        element.addEventListener('touchend', () => {
            element.style.opacity = '1';
        });
    });

    // Intersection Observer for fade animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '20px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    document.querySelectorAll('.fade-target').forEach(el => observer.observe(el));

    // Responsive image loading
    const imagesAll = document.querySelectorAll('img');
    imagesAll.forEach(img => {
        img.addEventListener('load', () => img.classList.add('loaded'));
        if (img.complete) img.classList.add('loaded');
    });

    // Handle orientation change
    window.addEventListener('orientationchange', () => {
        setTimeout(() => {
            window.scrollTo(0, window.scrollY);
        }, 100);
    });

    // Improve touch response
    document.addEventListener('touchstart', () => {}, {passive: true});

    // Handle newsletter form responsively
    const newsletterForm = document.querySelector('.newsletter-form');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', (e) => {
            if (window.innerWidth < 576) {
                // Add mobile-specific handling
                e.preventDefault();
                // Your form submission logic
            }
        });
    }
});

// Newsletter subscription handling
document.addEventListener('DOMContentLoaded', function() {
    const newsletterForm = document.getElementById('newsletterForm');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const email = this.querySelector('input[name="email"]').value;
            const csrfToken = this.querySelector('input[name="csrf_token"]').value;
            
            fetch('/subscribe-newsletter', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                // Show success message in a popup
                Swal.fire({
                    icon: data.status,
                    title: data.status === 'success' ? 'Thank You!' : 'Oops...',
                    text: data.message,
                    confirmButtonColor: '#007bff'
                });
                
                if (data.status === 'success') {
                    // Clear the form
                    newsletterForm.reset();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                Swal.fire({
                    icon: 'error',
                    title: 'Oops...',
                    text: 'Something went wrong! Please try again later.',
                    confirmButtonColor: '#007bff'
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