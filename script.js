document.addEventListener('DOMContentLoaded', () => {
    const pages = {
        home: document.getElementById('home'),
        input: document.getElementById('input'),
        output: document.getElementById('output'),
        faq: document.getElementById('faq')
    };

    let currentPage = 'home';

    // Navigation functions
    window.showPage = (pageName) => {
        if (pages[currentPage]) {
            pages[currentPage].classList.remove('active');
        }
        if (pages[pageName]) {
            pages[pageName].classList.add('active');
            currentPage = pageName;
        }
        updateFAQButton();
    };

    function updateFAQButton() {
        const faqButton = document.getElementById('faqButton');
        if (faqButton) {
            faqButton.style.display = currentPage === 'faq' ? 'none' : 'block';
        }
    }

    // Event Listeners
    document.getElementById('getStarted').addEventListener('click', () => {
        showPage('input');
    });

    document.getElementById('faqButton').addEventListener('click', () => {
        showPage('faq');
    });

    document.getElementById('backButton').addEventListener('click', () => {
        showPage('home');
    });

    document.getElementById('scanAgain').addEventListener('click', () => {
        document.getElementById('urlInput').value = '';
        document.getElementById('result').innerHTML = '';
        document.getElementById('urlDisplay').innerHTML = '';
        showPage('input');
    });

    // URL Scanning functionality
    document.getElementById('scanButton').addEventListener('click', async() => {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput.value.trim();

        if (!url) {
            alert('Please enter a valid URL');
            return;
        }

        const scanButton = document.getElementById('scanButton');
        scanButton.disabled = true;
        scanButton.textContent = 'Scanning...';

        try {
            const response = await fetch('http://localhost:5000/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            if (data.error) {
                throw new Error(data.error);
            }

            showPage('output');

            // Display results
            document.getElementById('urlDisplay').innerHTML = `
                <div style="word-break: break-all; margin: 10px 0; text-align: center;">
                    ${data.input_url}
                </div>
            `;

            const resultElement = document.getElementById('result');
            const resultText = data.is_phishing ?
                '⚠️ Potential Phishing URL Detected' :
                '✅ URL Appears to be Safe';

            resultElement.textContent = resultText;
            resultElement.className = data.is_phishing ? 'danger' : 'success';

        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred while scanning the URL. Please try again.');
        } finally {
            scanButton.disabled = false;
            scanButton.textContent = 'Scan';
        }
    });
});