// main.js - General functionality for the CyberShield app

document.addEventListener("DOMContentLoaded", function() {
    // Animation for risk meter
    const riskFill = document.querySelector('.risk-fill');
    if (riskFill) {
        const percentage = riskFill.getAttribute('data-percentage');
        setTimeout(() => {
            riskFill.style.width = `${percentage}%`;
        }, 300);
    }

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            template: '<div class="tooltip tooltip-custom" role="tooltip"><div class="tooltip-arrow"></div><div class="tooltip-inner"></div></div>'
        });
    });
});

// Notification helper function
function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} notification-toast`;
    notification.role = 'alert';
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi bi-${type === 'success' ? 'check-circle' : 'info-circle'} me-2"></i>
            <div>${message}</div>
        </div>
    `;

    // Style the notification
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        zIndex: '1050',
        minWidth: '300px',
        boxShadow: '0 5px 15px rgba(0,0,0,0.3)',
        backgroundColor: type === 'success' ? 'rgba(46, 213, 115, 0.9)' : 'rgba(0, 188, 212, 0.9)',
        color: 'white',
        borderRadius: '10px',
        opacity: '0',
        transition: 'opacity 0.3s ease'
    });

    // Add to document
    document.body.appendChild(notification);

    // Show notification with animation
    setTimeout(() => {
        notification.style.opacity = '1';
    }, 10);

    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 5000);
}