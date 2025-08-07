document.addEventListener('DOMContentLoaded', function() {
    // Debug check for Bootstrap
    if (typeof bootstrap === 'undefined') {
        console.error('Bootstrap is not loaded!');
        return;
    }

    // Prevent auto-hiding of all alerts within modals
    const preventAutoHide = (element) => {
        const alerts = element.querySelectorAll('.alert');
        alerts.forEach(alert => {
            // Add identifier class
            alert.classList.add('permanent-alert');
            
            // Remove any existing timeouts
            if (alert._timeoutId) {
                clearTimeout(alert._timeoutId);
            }
            
            // Remove close button if exists
            const closeBtn = alert.querySelector('.btn-close');
            if (closeBtn) {
                closeBtn.remove();
            }
            
            // Ensure visibility
            alert.style.display = 'block';
            alert.style.opacity = '1';
            alert.style.visibility = 'visible';
        });
    };

    // Initialize modals with permanent alerts
    document.querySelectorAll('.modal').forEach(modalElement => {
        // Remove any existing modal instances
        const existingModal = bootstrap.Modal.getInstance(modalElement);
        if (existingModal) {
            existingModal.dispose();
        }

        // Initialize new modal
        new bootstrap.Modal(modalElement);

        // Make alerts permanent
        preventAutoHide(modalElement);

        // Add show event listener to ensure alerts stay visible
        modalElement.addEventListener('shown.bs.modal', function() {
            preventAutoHide(this);
        });
    });

    // Handle cancel buttons
    document.querySelectorAll('[data-bs-toggle="modal"]').forEach(button => {
        button.addEventListener('click', function(e) {
            const targetModalId = this.getAttribute('data-bs-target');
            const targetModal = document.querySelector(targetModalId);
            
            if (targetModal) {
                const modal = bootstrap.Modal.getInstance(targetModal) || new bootstrap.Modal(targetModal);
                preventAutoHide(targetModal);
                modal.show();
            }
        });
    });

    // Prevent any dynamic alerts from being auto-hidden
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === 1 && node.classList && node.classList.contains('alert')) {
                    if (node.closest('.modal')) {
                        preventAutoHide(node.closest('.modal'));
                    }
                }
            });
        });
    });

    // Observe the entire document for dynamically added alerts
    observer.observe(document.body, {
        childList: true,
        subtree: true
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
});