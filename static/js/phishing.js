document.getElementById("urlForm").addEventListener("submit", function (e) {
    e.preventDefault();

    const url = document.getElementById("urlInput").value;
    const recaptcha = document.getElementById("recaptcha").checked;

    if (recaptcha) {
        fetch('/check-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById("resultText").innerText = data.result;
        })
        .catch(error => {
            console.error('Error:', error);
        });
    } else {
        alert("Please confirm you are not a robot.");
    }
});