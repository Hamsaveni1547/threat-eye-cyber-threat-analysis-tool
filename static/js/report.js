/**
 * Report generation and sharing functionality
 */

// Generate PDF report using html2pdf library
function generatePDF(reportId, reportType, title) {
  const reportContainer = document.getElementById('report-container');
  const loadingElement = document.getElementById('loading-indicator');

  if (loadingElement) {
    loadingElement.classList.remove('d-none');
  }

  // Create clone of the report to modify for PDF
  const reportClone = reportContainer.cloneNode(true);

  // Remove elements we don't want in the PDF
  const elementsToRemove = reportClone.querySelectorAll('.no-pdf');
  elementsToRemove.forEach(el => el.remove());

  // Add a header with the title
  const header = document.createElement('div');
  header.innerHTML = `
    <div style="text-align: center; margin-bottom: 20px;">
      <h1>${title}</h1>
      <p>Report generated on ${new Date().toLocaleString()}</p>
    </div>
  `;
  reportClone.prepend(header);

  // PDF generation options
  const options = {
    margin: 10,
    filename: `${reportType}_report_${reportId}.pdf`,
    image: { type: 'jpeg', quality: 0.98 },
    html2canvas: { scale: 2, useCORS: true },
    jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
  };

  // Generate PDF
  html2pdf().from(reportClone).set(options).save().then(() => {
    if (loadingElement) {
      loadingElement.classList.add('d-none');
    }
  });
}

// Download report as JSON
function downloadJSON(reportId, reportType) {
  window.location.href = `/download_report/${reportType}/${reportId}?format=json`;
}

// Download report as PDF
function downloadPDF(reportId, reportType) {
  window.location.href = `/download_report/${reportType}/${reportId}?format=pdf`;
}

// Share report via email
function shareViaEmail(reportId, reportType, subject) {
  const reportUrl = `${window.location.origin}/view_report/${reportType}/${reportId}`;
  const body = `Check out this security report: ${reportUrl}`;
  const mailtoLink = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  window.location.href = mailtoLink;
}

// Share report via link (copy to clipboard)
function shareViaLink(reportId, reportType) {
  const reportUrl = `${window.location.origin}/view_report/${reportType}/${reportId}`;

  // Use clipboard API if available
  if (navigator.clipboard) {
    navigator.clipboard.writeText(reportUrl).then(() => {
      const linkBtn = document.getElementById('copy-link-btn');
      const originalText = linkBtn.textContent;

      linkBtn.textContent = 'Link Copied!';
      linkBtn.classList.remove('btn-outline-primary');
      linkBtn.classList.add('btn-success');

      setTimeout(() => {
        linkBtn.textContent = originalText;
        linkBtn.classList.remove('btn-success');
        linkBtn.classList.add('btn-outline-primary');
      }, 2000);
    });
  } else {
    // Fallback for browsers that don't support Clipboard API
    const tempInput = document.createElement('input');
    document.body.appendChild(tempInput);
    tempInput.value = reportUrl;
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);

    alert('Link copied to clipboard!');
  }
}

// Function to format date and time
function formatDateTime(dateTimeStr) {
  const dt = new Date(dateTimeStr);
  return dt.toLocaleString();
}

// Add event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Handle download JSON button
  const jsonBtn = document.getElementById('download-json-btn');
  if (jsonBtn) {
    jsonBtn.addEventListener('click', function() {
      const reportId = this.getAttribute('data-report-id');
      const reportType = this.getAttribute('data-report-type');
      downloadJSON(reportId, reportType);
    });
  }

  // Handle download PDF button
  const pdfBtn = document.getElementById('download-pdf-btn');
  if (pdfBtn) {
    pdfBtn.addEventListener('click', function() {
      const reportId = this.getAttribute('data-report-id');
      const reportType = this.getAttribute('data-report-type');
      const title = this.getAttribute('data-title');
      generatePDF(reportId, reportType, title);
    });
  }

  // Handle share via email button
  const emailBtn = document.getElementById('share-email-btn');
  if (emailBtn) {
    emailBtn.addEventListener('click', function() {
      const reportId = this.getAttribute('data-report-id');
      const reportType = this.getAttribute('data-report-type');
      const subject = this.getAttribute('data-subject');
      shareViaEmail(reportId, reportType, subject);
    });
  }

  // Handle copy link button
  const linkBtn = document.getElementById('copy-link-btn');
  if (linkBtn) {
    linkBtn.addEventListener('click', function() {
      const reportId = this.getAttribute('data-report-id');
      const reportType = this.getAttribute('data-report-type');
      shareViaLink(reportId, reportType);
    });
  }

  // Format all date fields
  document.querySelectorAll('.format-date').forEach(function(element) {
    element.textContent = formatDateTime(element.textContent);
  });
});