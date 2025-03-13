// activities.js
document.addEventListener('DOMContentLoaded', function() {
    // Filter functionality
    const filterLinks = document.querySelectorAll('[data-filter]');
    filterLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const filter = this.getAttribute('data-filter');
            filterTable(filter);
        });
    });

    // Export functionality
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            exportActivities();
        });
    }

    // View details functionality
    const viewButtons = document.querySelectorAll('.view-details');
    viewButtons.forEach(button => {
        button.addEventListener('click', function() {
            const activityId = this.getAttribute('data-id');
            fetchActivityDetails(activityId);
        });
    });

    // Delete activity functionality
    const deleteButtons = document.querySelectorAll('.delete-activity');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const activityId = this.getAttribute('data-id');
            confirmDelete(activityId);
        });
    });

    // Download report functionality
    const downloadReportBtn = document.getElementById('downloadReport');
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', function() {
            const activityId = this.getAttribute('data-activity-id');
            downloadReport(activityId);
        });
    }
});

// Filter table rows based on status
function filterTable(status) {
    const rows = document.querySelectorAll('#activitiesTable tbody tr');

    rows.forEach(row => {
        if (status === 'all' || row.getAttribute('data-status') === status) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });

    // Update the filter button text
    const filterText = status.charAt(0).toUpperCase() + status.slice(1);
    document.getElementById('filterDropdown').innerHTML = `<i class="fas fa-filter me-1"></i> ${filterText}`;
}

// Export activities data
function exportActivities() {
    // Create a fetch request to the export endpoint
    fetch('/export-activities', {
        method: 'GET',
    })
    .then(response => response.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = 'activities_export.csv';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
    })
    .catch(error => {
        console.error('Error exporting activities:', error);
        alert('Failed to export activities. Please try again.');
    });
}

// Fetch and display activity details
function fetchActivityDetails(activityId) {
    // Show loading indicator
    const detailsContent = document.getElementById('activityDetailsContent');
    detailsContent.innerHTML = '<div class="text-center"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-2">Loading details...</p></div>';

    // Set the activity ID for the download report button
    document.getElementById('downloadReport').setAttribute('data-activity-id', activityId);

    // Show the modal
    const modal = new bootstrap.Modal(document.getElementById('activityDetailsModal'));
    modal.show();

    // Fetch the details
    fetch(`/activity-details/${activityId}`)
        .then(response => response.json())
        .then(data => {
            // Format the details and update the modal content
            detailsContent.innerHTML = formatActivityDetails(data);
        })
        .catch(error => {
            console.error('Error fetching activity details:', error);
            detailsContent.innerHTML = '<div class="alert alert-danger">Failed to load details. Please try again.</div>';
        });
}

// Format activity details for the modal
function formatActivityDetails(activity) {
    const statusClass = activity.status.toLowerCase() === 'clean' ? 'text-success' :
                       activity.status.toLowerCase() === 'suspicious' ? 'text-warning' : 'text-danger';

    let threatClass = 'bg-success';
    if (activity.threat_level >= 30 && activity.threat_level < 70) {
        threatClass = 'bg-warning';
    } else if (activity.threat_level >= 70) {
        threatClass = 'bg-danger';
    }

    return `
        <div class="row">
            <div class="col-md-6">
                <h6>Basic Information</h6>
                <table class="table table-sm">
                    <tr>
                        <th>Content</th>
                        <td>${activity.content}</td>
                    </tr>
                    <tr>
                        <th>Type</th>
                        <td><span class="badge ${activity.type.toLowerCase() === 'url' ? 'bg-primary' : 'bg-info'}">${activity.type}</span></td>
                    </tr>
                    <tr>
                        <th>Date Scanned</th>
                        <td>${activity.date}</td>
                    </tr>
                    <tr>
                        <th>Status</th>
                        <td><span class="${statusClass} fw-bold">${activity.status}</span></td>
                    </tr>
                    <tr>
                        <th>Threat Level</th>
                        <td>
                            <div class="progress" style="height: 10px;">
                                <div class="progress-bar ${threatClass}" role="progressbar" style="width: ${activity.threat_level}%"></div>
                            </div>
                            <small>${activity.threat_level}%</small>
                        </td>
                    </tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6>Threat Analysis</h6>
                <table class="table table-sm">
                    <tr>
                        <th>Scan Engine</th>
                        <td>${activity.scan_engine}</td>
                    </tr>
                    <tr>
                        <th>Scan Duration</th>
                        <td>${activity.scan_duration} seconds</td>
                    </tr>
                    <tr>
                        <th>Detected Threats</th>
                        <td>${activity.threats_detected || 0}</td>
                    </tr>
                </table>

                <h6 class="mt-3">Detected Issues</h6>
                <ul class="list-group">
                    ${activity.issues && activity.issues.length ?
                        activity.issues.map(issue =>
                            `<li class="list-group-item d-flex justify-content-between align-items-center">
                                ${issue.name}
                                <span class="badge ${issue.severity === 'High' ? 'bg-danger' : issue.severity === 'Medium' ? 'bg-warning' : 'bg-info'} rounded-pill">${issue.severity}</span>
                            </li>`
                        ).join('') :
                        '<li class="list-group-item text-muted">No issues detected</li>'
                    }
                </ul>
            </div>
        </div>

        <div class="row mt-4">
            <div class="col-12">
                <h6>Recommendations</h6>
                <div class="alert alert-light">
                    ${activity.recommendations || 'No specific recommendations available for this scan.'}
                </div>
            </div>
        </div>
    `;
}

// Confirm deletion of an activity
function confirmDelete(activityId) {
    if (confirm('Are you sure you want to delete this activity? This action cannot be undone.')) {
        deleteActivity(activityId);
    }
}

// Delete an activity
function deleteActivity(activityId) {
    fetch(`/delete-activity/${activityId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()  // Function to get CSRF token
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Remove the row from the table
            const row = document.querySelector(`button[data-id="${activityId}"]`).closest('tr');
            row.classList.add('fade-out');
            setTimeout(() => {
                row.remove();
                updateRowNumbers();
            }, 300);
        } else {
            alert('Failed to delete activity: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error deleting activity:', error);
        alert('An error occurred while deleting the activity. Please try again.');
    });
}

// Update row numbers after deletion
function updateRowNumbers() {
    const rows = document.querySelectorAll('#activitiesTable tbody tr');
    rows.forEach((row, index) => {
        row.querySelector('td:first-child').textContent = index + 1;
    });
}

// Get CSRF token from cookies
function getCsrfToken() {
    const name = 'csrftoken';
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Download a detailed report for an activity
function downloadReport(activityId) {
    window.location.href = `/download-report/${activityId}`;
}

// Add a new activity to the table (used when a new scan is performed)
function addNewActivity(activity) {
    const table = document.getElementById('activitiesTable');
    const tbody = table.querySelector('tbody');

    // Get current row count
    const rowCount = tbody.querySelectorAll('tr').length;

    // Create new row
    const row = document.createElement('tr');
    row.setAttribute('data-status', activity.status.toLowerCase());
    row.classList.add('fade-in');

    // Determine status and threat level classes
    let statusClass = 'status-clean';
    if (activity.status.toLowerCase() === 'suspicious') {
        statusClass = 'status-suspicious';
    } else if (activity.status.toLowerCase() === 'malicious') {
        statusClass = 'status-malicious';
    }

    let threatClass = 'bg-success';
    if (activity.threat_level >= 30 && activity.threat_level < 70) {
        threatClass = 'bg-warning';
    } else if (activity.threat_level >= 70) {
        threatClass = 'bg-danger';
    }

    // Set row content
    row.innerHTML = `
        <td>${rowCount + 1}</td>
        <td>${activity.content}</td>
        <td><span class="badge ${activity.type === 'URL' ? 'bg-primary' : 'bg-info'}">${activity.type}</span></td>
        <td>${activity.date}</td>
        <td><span class="status-badge ${statusClass}">${activity.status}</span></td>
        <td>
            <div class="progress" style="height: 8px;">
                <div class="progress-bar ${threatClass}" role="progressbar" style="width: ${activity.threat_level}%"></div>
            </div>
            <small class="text-muted">${activity.threat_level}%</small>
        </td>
        <td>
            <button class="btn btn-sm btn-info view-details" data-id="${activity.id}">
                <i class="fas fa-eye"></i>
            </button>
            <button class="btn btn-sm btn-danger delete-activity" data-id="${activity.id}">
                <i class="fas fa-trash"></i>
            </button>
        </td>
    `;

    // Add event listeners to new buttons
    const viewButton = row.querySelector('.view-details');
    viewButton.addEventListener('click', function() {
        fetchActivityDetails(this.getAttribute('data-id'));
    });

    const deleteButton = row.querySelector('.delete-activity');
    deleteButton.addEventListener('click', function() {
        confirmDelete(this.getAttribute('data-id'));
    });

    // Add row to table
    tbody.insertBefore(row, tbody.firstChild);
}