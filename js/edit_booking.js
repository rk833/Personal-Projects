document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('edit-booking-form');
    const checkIn = document.getElementById('check_in');
    const checkOut = document.getElementById('check_out');
    const numGuests = document.getElementById('num_guests');
    const bookingId = document.getElementById('booking_id');

    // Initialize flatpickr with proper callbacks
    const checkInPicker = flatpickr("#check_in", {
        minDate: "today",
        maxDate: new Date().fp_incr(90),
        dateFormat: "Y-m-d",
        onChange: function(selectedDates, dateStr) {
            if (selectedDates[0]) {
                const minCheckOut = new Date(selectedDates[0]);
                minCheckOut.setDate(minCheckOut.getDate() + 1);
                
                const maxCheckOut = new Date(selectedDates[0]);
                maxCheckOut.setDate(maxCheckOut.getDate() + 30);
                
                checkOutPicker.set('minDate', minCheckOut);
                checkOutPicker.set('maxDate', maxCheckOut);
                
                updatePrice();
            }
        }
    });

    const checkOutPicker = flatpickr("#check_out", {
        dateFormat: "Y-m-d",
        onChange: function(selectedDates) {
            if (selectedDates[0]) {
                updatePrice();
            }
        }
    });

    function updatePrice() {
        if (checkIn.value && checkOut.value && numGuests.value) {
            fetch(`/calculate_edit_price/${bookingId.value}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrf-token]').content
                },
                body: JSON.stringify({
                    check_in: checkIn.value,
                    check_out: checkOut.value,
                    num_guests: numGuests.value
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('base-price').textContent = 
                        `${data.currency_symbol}${data.base_price_per_night}`;
                    document.getElementById('num-nights').textContent = 
                        `${data.num_nights} night${data.num_nights > 1 ? 's' : ''}`;
                    document.getElementById('total-base-price').textContent = 
                        `${data.currency_symbol}${data.total_base_price}`;
                    document.getElementById('discount-rate').textContent = 
                        `${data.discount_rate}%`;
                    document.getElementById('discount-amount').textContent = 
                        `${data.currency_symbol}${data.discount_amount}`;
                    document.getElementById('final-price').textContent = 
                        `${data.currency_symbol}${data.final_price}`;
                } else {
                    // Show error message
                    const priceDetails = document.getElementById('price-details');
                    priceDetails.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                const priceDetails = document.getElementById('price-details');
                priceDetails.innerHTML = `<div class="alert alert-danger">An error occurred while calculating the price</div>`;
            });
        }
    }

    // Add event listeners
    numGuests.addEventListener('change', updatePrice);

    // Initial price calculation
    updatePrice();

    // Form submission handling
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Validate dates
        const checkInDate = new Date(checkIn.value);
        const checkOutDate = new Date(checkOut.value);
        const today = new Date();
        const maxDate = new Date();
        maxDate.setDate(today.getDate() + 90);
        
        if (checkInDate < today) {
            alert('Check-in date cannot be in the past');
            return;
        }
        
        if (checkInDate > maxDate) {
            alert('Cannot book more than 90 days in advance');
            return;
        }
        
        if (checkOutDate <= checkInDate) {
            alert('Check-out date must be after check-in date');
            return;
        }
        
        const stayDuration = (checkOutDate - checkInDate) / (1000 * 60 * 60 * 24);
        if (stayDuration > 30) {
            alert('Maximum stay duration is 30 days');
            return;
        }

        // If validation passes, submit the form
        form.submit();
    });
}); 