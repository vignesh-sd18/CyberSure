/**
 * Main JavaScript for the application
 * Handles animations, loading states, and interactive features
 */

// Loading Overlay Management
const loadingOverlay = {
    show: (message = 'Processing your request...') => {
        const overlay = document.getElementById('loading-overlay');
        const messageEl = overlay.querySelector('p');
        if (messageEl) messageEl.textContent = message;
        overlay.classList.remove('d-none');
        document.body.style.overflow = 'hidden';
    },
    hide: () => {
        const overlay = document.getElementById('loading-overlay');
        overlay.classList.add('d-none');
        document.body.style.overflow = 'auto';
    }
};

document.addEventListener('DOMContentLoaded', function() {
    // Navbar Scroll Behavior
    let lastScroll = 0;
    const navbar = document.querySelector('.navbar');
    
    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll <= 0) {
            navbar.classList.remove('navbar-scrolled', 'navbar-hidden');
            return;
        }

        if (currentScroll > lastScroll && !navbar.classList.contains('navbar-hidden')) {
            navbar.classList.add('navbar-hidden');
        } else if (currentScroll < lastScroll && navbar.classList.contains('navbar-hidden')) {
            navbar.classList.remove('navbar-hidden');
        }

        if (currentScroll > 100) {
            navbar.classList.add('navbar-scrolled');
        } else {
            navbar.classList.remove('navbar-scrolled');
        }

        lastScroll = currentScroll;
    });

    // Form submission handling with loading overlay
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            if (!form.classList.contains('search-form') && !form.hasAttribute('data-no-loading')) {
                const submitBtn = this.querySelector('button[type="submit"]');
                if (submitBtn) {
                    const originalText = submitBtn.innerHTML;
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
                    
                    loadingOverlay.show(form.getAttribute('data-loading-message') || 'Processing your request...');
                    
                    // Re-enable button after 30 seconds (failsafe)
                    setTimeout(() => {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = originalText;
                        loadingOverlay.hide();
                    }, 30000);
                }
            }
        });
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('fade');
            setTimeout(() => alert.remove(), 150);
        }, 5000);
    });

    // Add animation classes to elements
    const animatedElements = document.querySelectorAll('.card, .stats-card, .alert');
    animatedElements.forEach((el, index) => {
        el.style.opacity = '0';
        el.style.animation = `fadeIn 0.5s ease forwards ${index * 0.1}s`;
    });

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Handle blockchain transaction states
    const transactionButtons = document.querySelectorAll('.blockchain-action');
    transactionButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            this.disabled = true;
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing Transaction...';
            
            // Simulate blockchain transaction (replace with actual blockchain interaction)
            setTimeout(() => {
                this.innerHTML = '<i class="fas fa-check"></i> Transaction Complete';
                this.classList.remove('btn-primary');
                this.classList.add('btn-success');
            }, 2000);
        });
    });

    // Form validation
    const validateForm = (form) => {
        let isValid = true;
        const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
        
        inputs.forEach(input => {
            if (!input.value.trim()) {
                isValid = false;
                input.classList.add('is-invalid');
                
                // Create or update validation message
                let feedback = input.nextElementSibling;
                if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                    feedback = document.createElement('div');
                    feedback.classList.add('invalid-feedback');
                    input.parentNode.insertBefore(feedback, input.nextSibling);
                }
                feedback.textContent = 'This field is required';
            } else {
                input.classList.remove('is-invalid');
                const feedback = input.nextElementSibling;
                if (feedback && feedback.classList.contains('invalid-feedback')) {
                    feedback.remove();
                }
            }
        });
        
        return isValid;
    };

    // Apply validation to all forms
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
                e.stopPropagation();
            }
        });
    });

    // Responsive table handling
    const tables = document.querySelectorAll('.table-responsive');
    tables.forEach(table => {
        if (table.scrollWidth > table.clientWidth) {
            const scrollIndicator = document.createElement('div');
            scrollIndicator.classList.add('scroll-indicator');
            scrollIndicator.innerHTML = '<i class="fas fa-arrows-left-right"></i> Scroll to see more';
            table.parentNode.insertBefore(scrollIndicator, table);
        }
    });
});

// Prediction loading state handler
function showPredictionLoading() {
    const predictionResult = document.getElementById('prediction-result');
    if (predictionResult) {
        predictionResult.innerHTML = `
            <div class="text-center p-4">
                <div class="loading-spinner mx-auto"></div>
                <p class="mt-3">Analyzing risk factors...</p>
            </div>
        `;
    }
}

// Chart animation handler
function animateChart(chart) {
    let currentPercentage = 0;
    const targetPercentage = chart.dataset.percentage;
    const duration = 1500;
    const increment = (targetPercentage / duration) * 16.67; // 60fps

    const animation = setInterval(() => {
        if (currentPercentage >= targetPercentage) {
            clearInterval(animation);
            currentPercentage = targetPercentage;
        }
        chart.style.setProperty('--percentage', `${currentPercentage}%`);
        currentPercentage += increment;
    }, 16.67);
}