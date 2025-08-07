document.addEventListener('DOMContentLoaded', function() {
    // Navbar toggler
    const navbarCollapse = document.querySelector('.navbar-collapse');

    if (navbarToggler) {
        navbarToggler.addEventListener('click', function() {
            navbarCollapse.classList.toggle('show');
        });
    }

    // Profile Dropdown
    const profileToggle = document.querySelector('.profile-toggle');
    const profileMenu = document.querySelector('.profile-menu');

    if (profileToggle && profileMenu) {
        profileToggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            // Toggle menu
            profileMenu.classList.toggle('show');
            
            // Keep navbar open in mobile
            if (window.innerWidth < 992) {
                navbarCollapse.classList.add('show');
            }
        });

        // Close when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.nav-item.dropdown')) {
                profileMenu.classList.remove('show');
            }
        });

        // Prevent menu clicks from closing navbar
        profileMenu.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }

    // Close navbar when clicking outside (except for dropdown)
    document.addEventListener('click', function(e) {
        if (!navbarCollapse.contains(e.target) && 
            !navbarToggler.contains(e.target) && 
            !e.target.closest('.nav-item.dropdown')) {
            navbarCollapse.classList.remove('show');
        }
    });

    // Back to Top Button
    const backToTopButton = document.getElementById("back-to-top");
    
    if (backToTopButton) {
        // Show button when page is scrolled
        window.addEventListener("scroll", function() {
            if (window.scrollY > 300) {
                backToTopButton.style.display = "flex";
            } else {
                backToTopButton.style.display = "none";
            }
        });

        // Smooth scroll to top when clicked
        backToTopButton.addEventListener("click", function() {
            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });
        });
    }
});
