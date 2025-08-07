document.addEventListener("DOMContentLoaded", () => {
  const elements = document.querySelectorAll(".fade-target");
  
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry, index) => {
        if (entry.isIntersecting) {
          setTimeout(() => {
            entry.target.classList.add("fade-in-up");
          }, index * 200); // 200ms delay between each element
          observer.unobserve(entry.target); // Stop observing once animated
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

document.addEventListener('DOMContentLoaded', function () {
    const checkInInput = document.querySelector('input[name="check_in"]');
    const checkOutInput = document.querySelector('input[name="check_out"]');

    // Get today's date
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Calculate max date (3 months from today)
    const maxDate = new Date(today);
    maxDate.setMonth(maxDate.getMonth() + 3);

    // Format dates for input min/max attributes
    const todayStr = today.toISOString().split('T')[0];
    const maxDateStr = maxDate.toISOString().split('T')[0];

    // Set initial min/max dates for check-in
    checkInInput.min = todayStr;
    checkInInput.max = maxDateStr;

    // Update check-out min/max when check-in changes
    checkInInput.addEventListener('change', function () {
        const selectedCheckIn = new Date(this.value);
        
        // Set minimum check-out to day after check-in
        const minCheckOut = new Date(selectedCheckIn);
        minCheckOut.setDate(minCheckOut.getDate() + 1);
        
        // Set maximum check-out to either 30 days after check-in or 3 months from today
        const thirtyDaysFromCheckIn = new Date(selectedCheckIn);
        thirtyDaysFromCheckIn.setDate(thirtyDaysFromCheckIn.getDate() + 30);
        
        const maxCheckOut = new Date(Math.min(thirtyDaysFromCheckIn, maxDate));

        checkOutInput.min = minCheckOut.toISOString().split('T')[0];
        checkOutInput.max = maxCheckOut.toISOString().split('T')[0];

        // If current check-out date is invalid, clear it
        const currentCheckOut = new Date(checkOutInput.value);
        if (currentCheckOut < minCheckOut || currentCheckOut > maxCheckOut) {
            checkOutInput.value = '';
        }
    });

    // Add validation for check-out date
    checkOutInput.addEventListener('change', function() {
        const checkInDate = new Date(checkInInput.value);
        const checkOutDate = new Date(this.value);
        const daysDifference = (checkOutDate - checkInDate) / (1000 * 60 * 60 * 24);

        if (daysDifference > 30) {
            alert('Maximum stay duration is 30 days');
            this.value = '';
        }
    });

    // Initialize check-out min/max if check-in has a value
    if (checkInInput.value) {
        checkInInput.dispatchEvent(new Event('change'));
    }

    // Add tooltips to explain date restrictions
    checkInInput.title = 'Select a date within the next 3 months';
    checkOutInput.title = 'Maximum stay duration is 30 days';
});
