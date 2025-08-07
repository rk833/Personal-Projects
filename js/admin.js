document.addEventListener('DOMContentLoaded', function() {
    // Sidebar toggle
    document.getElementById('sidebarCollapse').addEventListener('click', function() {
        document.getElementById('sidebar').classList.toggle('active');
    });

    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        $('.alert').alert('close');
    }, 5000);

    // Prevent form double submission
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            if (this.submitted) {
                e.preventDefault();
                return;
            }
            this.submitted = true;
        });
    });

    // Add loading state to date range selector
    document.querySelector('select[name="range"]')?.addEventListener('change', function() {
        this.disabled = true;
        this.form.submit();
    });
});

// Chart.js defaults
Chart.defaults.color = '#666';
Chart.defaults.font.family = "'Nunito', 'sans-serif'";

// Function to format numbers with commas
function numberWithCommas(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Function to format currency
function formatCurrency(amount) {
    return '£' + numberWithCommas(parseFloat(amount).toFixed(2));
}