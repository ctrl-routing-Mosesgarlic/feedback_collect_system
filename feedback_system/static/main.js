// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});
// Add to your main.js
document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            if (alert) {
                alert.classList.remove('show');
                setTimeout(() => alert.remove(), 300);
            }
        }, 5000);
    });
});

// Add this to your JavaScript
const fetchWithCSRF = (url, options = {}) => {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    
    return fetch(url, {
        ...options,
        headers: {
            'X-CSRFToken': csrfToken,
            'Content-Type': 'application/json',
            ...(options.headers || {})
        }
    });
};

// Create a utility function for making fetch requests
function fetchWithCSRF(url, options = {}) {
    // Get the CSRF token from the meta tag
    const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
    
    // Set default headers
    const defaultHeaders = {
        'X-CSRFToken': csrfToken,
        'Content-Type': 'application/json',
    };

    // Merge default options with provided options
    const fetchOptions = {
        ...options,
        headers: {
            ...defaultHeaders,
            ...(options.headers || {})
        }
    };

    return fetch(url, fetchOptions);
}

// For general feedback
fetchWithCSRF(`/general_feedback/${campaignId}`, {
    method: 'POST',
    body: JSON.stringify({
        
    })
})
.then(response => {
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
})
.then(data => {
    if (data.success) {
        console.log('Success:', data);
    }
})
.catch(error => {
    console.error('Error:', error);
});

// For docket feedback
fetchWithCSRF('/docket_feedback/123', {
    method: 'POST',
    body: JSON.stringify(data)
})

// For service feedback
fetchWithCSRF('/service_feedback/123', {
    method: 'POST',
    body: JSON.stringify(data)
})

// If you have the campaign ID in your page somewhere
const campaignId = document.querySelector('[data-campaign-id]').dataset.campaignId;

// Then use it in your fetch call
fetchWithCSRF(`/general_feedback/${campaignId}`, {
    method: 'POST',
    body: JSON.stringify(data)
})
// Handle form submission
document.querySelector('form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const data = Object.fromEntries(formData);
    
    fetchWithCSRF('/your-endpoint', {
        method: 'POST',
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        // Handle success
    })
    .catch(error => {
        // Handle error
    });
});

fetch('/docket_feedback', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
})

    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
            
        })
function searchForms() {
    const searchTerm = document.getElementById('searchInput').value;
    fetch(`/api/forms/search?term=${encodeURIComponent(searchTerm)}`)
        .then(response => response.json())
        .then(forms => {
            // Display forms
            displayForms(forms);
        });
}

// # In your frontend JavaScript
function generateQRCode(formId) {
    window.open(`/api/forms/${formId}/qr`, '_blank');
}
