document.addEventListener('DOMContentLoaded', function() {
    // Ensure all interactive elements have proper event handling
    document.querySelectorAll('button, a, input, textarea').forEach(element => {
        element.style.position = 'relative';
        element.style.zIndex = '5';
    });

    // Prevent map from capturing events
    const mapSection = document.querySelector('.map-section');
    if (mapSection) {
        mapSection.addEventListener('touchstart', function(e) {
            e.stopPropagation();
        }, true);
    }

    const form = document.getElementById('contact-form');
    
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        e.stopPropagation(); // Prevent event bubbling
        
        const submitButton = form.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.innerHTML = 'Sending...';
        
        try {
            const formData = new FormData(form);
            
            const response = await fetch('/contact', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': formData.get('csrf_token')
                }
            });
            
            const data = await response.json();
            
            // Create flash message
            const flashMessagesContainer = document.querySelector('.flash-messages');
            const alertDiv = document.createElement('div');
            
            if (response.ok) {
                // Success case
                alertDiv.className = 'alert alert-success fade show';
                alertDiv.innerHTML = `
                    <div class="alert-content">
                        <i class="fas fa-check-circle"></i>
                        <span>Your message has been sent successfully!</span>
                    </div>
                    <button type="button" class="btn-close">
                        <span>&times;</span>
                    </button>
                `;
                
                // Reset form
                form.reset();
            } else {
                // Error case
                alertDiv.className = 'alert alert-danger fade show';
                alertDiv.innerHTML = `
                    <div class="alert-content">
                        <i class="fas fa-exclamation-circle"></i>
                        <span>${data.message || 'An error occurred. Please try again.'}</span>
                    </div>
                    <button type="button" class="btn-close">
                        <span>&times;</span>
                    </button>
                `;
            }
            
            // Add the alert to the container
            flashMessagesContainer.appendChild(alertDiv);
            
            // Scroll to the message
            alertDiv.scrollIntoView({ behavior: 'smooth', block: 'center' });
            
        } catch (error) {
            console.error('Error:', error);
            // Create error message
            const flashMessagesContainer = document.querySelector('.flash-messages');
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-danger fade show';
            alertDiv.innerHTML = `
                <div class="alert-content">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>There was an error sending your message. Please try again.</span>
                </div>
                <button type="button" class="btn-close">
                    <span>&times;</span>
                </button>
            `;
            flashMessagesContainer.appendChild(alertDiv);
        } finally {
            submitButton.disabled = false;
            submitButton.innerHTML = 'Send';
        }
    });
    
    // Initialize close buttons for flash messages
    document.addEventListener('click', function(e) {
        if (e.target.closest('.btn-close')) {
            const alert = e.target.closest('.alert');
            if (alert) {
                alert.classList.remove('show');
                setTimeout(() => {
                    alert.remove();
                }, 300);
            }
        }
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

    // Ensure back to top button works
    const backToTopButton = document.getElementById("back-to-top");
    if (backToTopButton) {
        backToTopButton.style.zIndex = '1060'; // Place above everything
        window.addEventListener("scroll", () => {
            backToTopButton.style.display = window.scrollY > 300 ? "flex" : "none";
        });

        backToTopButton.addEventListener("click", () => {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }
});