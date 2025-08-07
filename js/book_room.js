document.addEventListener("DOMContentLoaded", function () {
    const checkInInput = document.querySelector('input[name="check_in"]');
    const checkOutInput = document.querySelector('input[name="check_out"]');
    const guestsSelect = document.querySelector('select[name="num_guests"]');
    const form = document.getElementById('bookingForm');
    const pricingInfo = document.querySelector('.pricing-info .card-body');

    // Get today's date
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Calculate max date (3 months from today)
    const maxDate = new Date(today);
    maxDate.setMonth(maxDate.getMonth() + 3);

    // Set initial min/max dates for check-in
    checkInInput.min = today.toISOString().split('T')[0];
    checkInInput.max = maxDate.toISOString().split('T')[0];

    // Add debounce to prevent too many requests
    let updateTimeout;
    function updatePricing() {
        clearTimeout(updateTimeout);
        updateTimeout = setTimeout(() => {
            if (checkInInput.value && checkOutInput.value) {
                const checkIn = new Date(checkInInput.value);
                const checkOut = new Date(checkOutInput.value);
                const stayDuration = (checkOut - checkIn) / (1000 * 60 * 60 * 24);

                // Validate dates before making request
                if (checkIn > maxDate) {
                    alert('Bookings can only be made up to 3 months in advance');
                    return;
                }
                if (stayDuration > 30) {
                    alert('Maximum stay duration is 30 days');
                    return;
                }

                // Make AJAX request
                fetch(`/calculate_price/{{ room.room_id }}?check_in=${checkInInput.value}&check_out=${checkOutInput.value}&num_guests=${guestsSelect.value}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            console.error(data.error);
                            return;
                        }

                        let html = `
                            <div class="d-flex justify-content-between mb-2">
                                <span>Base price per night:</span>
                                <span>${data.currency_symbol}${data.base_price_per_night.toFixed(2)}</span>
                            </div>
                            <div class="d-flex justify-content-between mb-2">
                                <span>Number of nights:</span>
                                <span>${data.num_nights}</span>
                            </div>
                            <div class="d-flex justify-content-between mb-2">
                                <span>Total base price:</span>
                                <span>${data.currency_symbol}${data.total_base_price.toFixed(2)}</span>
                            </div>`;

                        if (data.discount_rate > 0) {
                            html += `
                                <div class="discount-alert alert alert-success py-1 mb-2">
                                    <small>${data.discount_rate}% advance booking discount applied!</small>
                                </div>
                                <div class="d-flex justify-content-between text-success">
                                    <span>Discount amount:</span>
                                    <span>-${data.currency_symbol}${data.discount_amount.toFixed(2)}</span>
                                </div>
                                <div class="d-flex justify-content-between fw-bold mt-2">
                                    <span>Final price:</span>
                                    <span>${data.currency_symbol}${data.final_price.toFixed(2)}</span>
                                </div>`;
                        }

                        pricingInfo.innerHTML = html;
                    })
                    .catch(error => console.error('Error:', error));
            }
        }, 500); // Wait 500ms after last change
    }

    // Add event listeners
    checkInInput.addEventListener("change", function() {
        // Set minimum check-out to day after check-in
        const minCheckOut = new Date(this.value);
        minCheckOut.setDate(minCheckOut.getDate() + 1);
        
        // Set maximum check-out to either 30 days after check-in or 3 months from today
        const thirtyDaysFromCheckIn = new Date(this.value);
        thirtyDaysFromCheckIn.setDate(thirtyDaysFromCheckIn.getDate() + 30);
        
        const maxCheckOut = new Date(Math.min(thirtyDaysFromCheckIn, maxDate));

        checkOutInput.min = minCheckOut.toISOString().split('T')[0];
        checkOutInput.max = maxCheckOut.toISOString().split('T')[0];
        
        // Clear check-out if it's now invalid
        if (checkOutInput.value) {
            const checkOutDate = new Date(checkOutInput.value);
            if (checkOutDate <= minCheckOut || checkOutDate > maxCheckOut) {
                checkOutInput.value = '';
            } else {
                updatePricing();
            }
        }
    });

    checkOutInput.addEventListener("change", updatePricing);
    guestsSelect.addEventListener("change", updatePricing);

    // Form validation before submission
    form.addEventListener('submit', function(e) {
        const checkIn = new Date(checkInInput.value);
        const checkOut = new Date(checkOutInput.value);
        
        if (checkIn < today) {
            e.preventDefault();
            alert('Check-in date cannot be in the past');
            return;
        }

        if (checkOut <= checkIn) {
            e.preventDefault();
            alert('Check-out date must be after check-in date');
            return;
        }
        
        const stayDuration = (checkOut - checkIn) / (1000 * 60 * 60 * 24);
        if (stayDuration > 30) {
            e.preventDefault();
            alert('Maximum stay duration is 30 days');
            return;
        }

        if (checkIn > maxDate) {
            e.preventDefault();
            alert('Bookings can only be made up to 3 months in advance');
            return;
        }
    });

    // Initialize check-out min/max if check-in has a value
    if (checkInInput.value) {
        checkInInput.dispatchEvent(new Event('change'));
    }

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

    // Policies popup
    const policiesPopup = document.getElementById('policiesPopup');
    const closePopup = document.getElementById('closePopup');

    if (closePopup) {
        closePopup.addEventListener('click', function() {
            policiesPopup.style.display = 'none';
        });
    }

    // Close popup when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === policiesPopup) {
            policiesPopup.style.display = 'none';
        }
    });

    // Function to prevent auto-hiding of alerts
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

    // Prevent auto-hiding for discount alerts in pricing info
    const pricingInfoContainer = document.querySelector('.pricing-info');
    if (pricingInfoContainer) {
        preventAutoHide(pricingInfoContainer);
    }

    // Create observer for dynamically added alerts
    const dynamicObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === 1) {
                    // Check for discount messages
                    if (node.classList && node.classList.contains('alert') && 
                        (node.textContent.includes('discount applied') || 
                         node.textContent.includes('cancellation charge'))) {
                        node.classList.add('permanent-alert');
                        const closeBtn = node.querySelector('.btn-close');
                        if (closeBtn) {
                            closeBtn.remove();
                        }
                        node.style.display = 'block';
                        node.style.opacity = '1';
                        node.style.visibility = 'visible';
                    }
                    // Check for pricing info container
                    if (node.querySelector && node.querySelector('.pricing-info')) {
                        preventAutoHide(node.querySelector('.pricing-info'));
                    }
                }
            });
        });
    });

    // Observe the entire document
    dynamicObserver.observe(document.body, {
        childList: true,
        subtree: true
    });
});

// Show the popup as soon as the user enters the booking page or reloads
window.addEventListener('load', function() {
    const popup = document.getElementById('policiesPopup');
    popup.style.display = 'flex';
});

// Close the popup when the close button is clicked
document.getElementById('closePopup').addEventListener('click', function() {
    const popup = document.getElementById('policiesPopup');
    popup.style.display = 'none';
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