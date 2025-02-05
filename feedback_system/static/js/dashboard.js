// static/js/dashboard.js

// Get CSRF token from meta tag
function getCSRFToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

// Show form search section
function showFormSearch() {
    document.getElementById('formSearchSection').style.display = 'block';
}

// Search forms with CSRF protection
function searchForms() {
    const searchTerm = document.getElementById('formSearchInput').value;
    fetch(`/search_forms?term=${searchTerm}`, {
        method: 'GET',
        headers: {
            'X-CSRFToken': getCSRFToken(),
            'Accept': 'application/json',
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(forms => {
        const resultsDiv = document.getElementById('searchResults');
        resultsDiv.innerHTML = forms.map(form => `
            <div class="card mt-2">
                <div class="card-body">
                    <h5 class="card-title">${form.name}</h5>
                    <button onclick="previewForm('${form.id}')" class="btn btn-info">Preview</button>
                </div>
            </div>
        `).join('');
    })
    .catch(error => console.error('Error searching forms:', error));
}

// Preview form with CSRF protection
function previewForm(formId) {
    fetch(`/get_form_preview/${formId}`, {
        method: 'GET',
        headers: {
            'X-CSRFToken': getCSRFToken(),
            'Accept': 'application/json',
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(form => {
        document.getElementById('previewContent').innerHTML = form.content;
        document.getElementById('formPreview').style.display = 'block';
        document.getElementById('searchResults').style.display = 'none';
        // Store the current form ID globally
        window.currentFormId = formId;
    })
    .catch(error => console.error('Error previewing form:', error));
}

// Go back to search
function goBackToSearch() {
    document.getElementById('formPreview').style.display = 'none';
    document.getElementById('searchResults').style.display = 'block';
    document.getElementById('downloadSection').style.display = 'none';
    document.getElementById('qrcodeSection').style.display = 'none';
    document.getElementById('actionSelect').value = '';
}

// Handle action change
function handleActionChange() {
    const action = document.getElementById('actionSelect').value;
    document.getElementById('downloadSection').style.display = action === 'download' ? 'block' : 'none';
    document.getElementById('qrcodeSection').style.display = action === 'qrcode' ? 'block' : 'none';

    if (action === 'qrcode') {
        generateQRCode();
    }
}

// Download template with CSRF protection
function downloadTemplate() {
    if (!window.currentFormId) {
        console.error('No form selected');
        return;
    }
    
    window.location.href = `/download_template/${window.currentFormId}`;
}

// Function to handle custom QR code generation form submission
function handleCustomQRSubmission(event) {
    event.preventDefault();
    
    if (!event.target) {
        console.error('No form data available');
        return;
    }

    const formData = new FormData(event.target);
    
    fetch('/generate', {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCSRFToken(),
        },
        credentials: 'same-origin',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.blob();
    })
    .then(blob => {
        // Create and trigger download
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'qr_code.png';
        document.body.appendChild(a);
        a.click();
        
        // Clean up
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    })
    .catch(error => console.error('Error generating custom QR code:', error));
}

// Generate QR code with CSRF protection
function generateQRCode() {
    if (!window.currentFormId) {
        console.error('No form selected');
        return;
    }

    fetch(`/generate_qrcode/${window.currentFormId}`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCSRFToken(),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin',
        body: JSON.stringify({
            formId: window.currentFormId
        })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('qrcodeDisplay').innerHTML = `
            <img src="data:image/png;base64,${data.qr_code}" alt="QR Code">
        `;
    })
    .catch(error => console.error('Error generating QR code:', error));
}

