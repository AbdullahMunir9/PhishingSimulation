// static/script.js
document.addEventListener("DOMContentLoaded", function() {
    const form = document.getElementById('emailForm');
    const loadingIndicator = document.getElementById('loading');

    form.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent default form submission

        const emailInput = document.getElementById('email');
        const email = emailInput.value.trim();

        // Simple email validation (basic regex)
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailPattern.test(email)) {
            alert("Please enter a valid email address.");
            return;
        }

        // Show loading indicator
        loadingIndicator.style.display = 'block';

        // Send the form data using fetch API (POST JSON)
        fetch('/send_phishing_email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        })
        .then(async response => {
            loadingIndicator.style.display = 'none';
            if (!response.ok) {
                const err = await response.json().catch(async ()=>({message: await response.text()}));
                alert("Error: " + (err.message || "Failed to send"));
                return;
            }
            const data = await response.json();
            alert(data.message || "Email sent");
            form.reset();
        })
        .catch(error => {
            loadingIndicator.style.display = 'none';
            alert("An error occurred while sending the email. Please try again.");
            console.error("Error:", error);
        });
    });
});
