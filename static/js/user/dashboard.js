document.addEventListener('DOMContentLoaded', function() {
    // Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');

    sidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('active');
        mainContent.classList.toggle('full-width');
    });

    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Settings Modal
    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            const settingsModal = new bootstrap.Modal(document.getElementById('settingsModal'));
            settingsModal.show();
        });
    }

    // Load Recent Activities
    loadRecentActivities();

    // User dropdown functionality
    const userInfoToggle = document.getElementById('userInfoToggle');
    const userDropdown = document.querySelector('.user-dropdown');
    
    userInfoToggle.addEventListener('click', function(e) {
        e.stopPropagation();
        userDropdown.classList.toggle('show');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (!userDropdown.contains(e.target) && !userInfoToggle.contains(e.target)) {
            userDropdown.classList.remove('show');
        }
    });
});

function loadRecentActivities() {
    const activityList = document.querySelector('.activity-list');
    if (!activityList) return;

    // Sample activities - Replace with actual data from backend
    const activities = [
        { type: 'scan', title: 'Website Scan', time: '2 minutes ago', status: 'success' },
        { type: 'check', title: 'Email Check', time: '1 hour ago', status: 'warning' },
        { type: 'analysis', title: 'IP Analysis', time: '3 hours ago', status: 'success' },
        { type: 'login', title: 'Login Activity', time: '1 day ago', status: 'info' }
    ];

    activities.forEach(activity => {
        const activityItem = createActivityItem(activity);
        activityList.appendChild(activityItem);
    });
}

function createActivityItem(activity) {
    const div = document.createElement('div');
    div.className = `activity-item ${activity.status}`;
    div.innerHTML = `
        <i class="fas fa-${getActivityIcon(activity.type)}"></i>
        <div class="activity-info">
            <h4>${activity.title}</h4>
            <p>${activity.time}</p>
        </div>
        <span class="status-badge ${activity.status}">
            ${activity.status}
        </span>
    `;
    return div;
}

function getActivityIcon(type) {
    const icons = {
        scan: 'search',
        check: 'check-circle',
        analysis: 'chart-line',
        login: 'sign-in-alt'
    };
    return icons[type] || 'info-circle';
}
