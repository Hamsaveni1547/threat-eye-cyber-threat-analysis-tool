// reports.js - Handles PDF report generation functionality

document.addEventListener('DOMContentLoaded', function() {
    const reportButton = document.querySelector('.btn-report');
    if (reportButton) {
        reportButton.addEventListener('click', generatePDFReport);
    }
});

function generatePDFReport() {
    const reportButton = document.querySelector('.btn-report');
    const ipAddress = document.querySelector('.ip-badge').textContent;
    const reportFileName = `IP_Analysis_Report_${ipAddress.trim()}.pdf`;

    // Show loading state
    const originalText = reportButton.innerHTML;
    reportButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Generating...';
    reportButton.disabled = true;

    // Collect report data
    const reportData = {
        ipAddress: ipAddress,
        ipType: document.querySelector('.info-row:nth-child(1) .info-value').textContent,
        organization: document.querySelector('.info-row:nth-child(2) .info-value').textContent,
        location: document.querySelector('.info-row:nth-child(3) .info-value').textContent,
        riskLevel: document.querySelector('.risk-level').textContent,
        riskPercentage: document.querySelector('.risk-fill').getAttribute('data-percentage') + '%',
        date: new Date().toLocaleString()
    };

    // Send data to server for PDF generation
    fetch('/api/generate_report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(reportData)
    })
    .then(response => response.json())
    .then(data => {
        // Reset button
        reportButton.innerHTML = originalText;
        reportButton.disabled = false;

        if (data.success) {
            // Show success notification
            showNotification('Report generated successfully! Downloading PDF...', 'success');

            // Start download
            setTimeout(function() {
                window.location.href = `/api/download_report/${data.filename}`;
            }, 1000);
        } else {
            showNotification('Failed to generate report: ' + data.message, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        reportButton.innerHTML = originalText;
        reportButton.disabled = false;
        showNotification('An error occurred while generating the report', 'danger');
    });
}