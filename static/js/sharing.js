// sharing.js - Handles sharing functionality

document.addEventListener('DOMContentLoaded', function() {
    const shareButton = document.querySelector('.btn-share');
    if (shareButton) {
        shareButton.addEventListener('click', openShareDialog);
    }
});

function openShareDialog() {
    const ipAddress = document.querySelector('.ip-badge').textContent.trim();

    // Create modal overlay
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1060;
        backdrop-filter: blur(5px);
    `;

    // Create modal content
    const modal = document.createElement('div');
    modal.className = 'share-modal';
    modal.style.cssText = `
        background-color: var(--dark-color);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 15px;
        width: 90%;
        max-width: 500px;
        padding: 30px;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.3);
    `;

    // Create modal header
    const header = document.createElement('div');
    header.style.cssText = `
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
    `;

    const title = document.createElement('h4');
    title.textContent = 'Share Analysis Results';
    title.style.margin = '0';

    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '<i class="bi bi-x-lg"></i>';
    closeBtn.style.cssText = `
        background: none;
        border: none;
        color: white;
        font-size: 1.2rem;
        cursor: pointer;
    `;
    closeBtn.onclick = function() {
        document.body.removeChild(overlay);
    };

    header.appendChild(title);
    header.appendChild(closeBtn);

    // Create sharing options
    const options = document.createElement('div');

    // Link sharing
    const linkSection = document.createElement('div');
    linkSection.style.marginBottom = '20px';

    const linkLabel = document.createElement('p');
    linkLabel.textContent = 'Share direct link:';
    linkLabel.style.cssText = `
        margin-bottom: 10px;
        font-weight: 500;
    `;

    const linkInput = document.createElement('div');
    linkInput.style.cssText = `
        display: flex;
        gap: 10px;
    `;

    const shareUrl = `https://cybershield.example.com/analysis/${ipAddress}`;