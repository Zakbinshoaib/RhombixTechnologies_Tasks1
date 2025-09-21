// Mobile Application Security Assessment Tool - JavaScript
// Rhombix Technologies - Cybersecurity Internship Task 1

// Vulnerability database - OWASP Mobile Top 10
const vulnerabilities = [
    {
        id: 'M2',
        title: 'Insecure Data Storage',
        severity: 'high',
        description: 'Sensitive data stored in unencrypted format in local databases, shared preferences, or external storage.',
        impact: 'Attackers can access sensitive user data, authentication tokens, and personal information stored on the device.',
        location: '/data/data/com.app/shared_prefs/user_prefs.xml',
        owasp: 'OWASP Mobile Top 10 2016 - M2'
    },
    {
        id: 'M4',
        title: 'Insecure Authentication',
        severity: 'high',
        description: 'Weak authentication mechanisms allowing easy bypass or credential theft.',
        impact: 'Unauthorized access to user accounts and sensitive application functionality.',
        location: 'Authentication module - login.java:45',
        owasp: 'OWASP Mobile Top 10 2016 - M4'
    },
    {
        id: 'M3',
        title: 'Insecure Communication',
        severity: 'medium',
        description: 'Network communications not properly encrypted or using weak encryption protocols.',
        impact: 'Man-in-the-middle attacks can intercept sensitive data during transmission.',
        location: 'API endpoints: api.example.com/login',
        owasp: 'OWASP Mobile Top 10 2016 - M3'
    },
    {
        id: 'M5',
        title: 'Insufficient Cryptography',
        severity: 'medium',
        description: 'Use of weak encryption algorithms or improper implementation of cryptographic functions.',
        impact: 'Encrypted data can be easily decrypted by attackers using modern computing power.',
        location: 'CryptoManager.java:78 - MD5 hash usage',
        owasp: 'OWASP Mobile Top 10 2016 - M5'
    },
    {
        id: 'M7',
        title: 'Client Side Injection',
        severity: 'medium',
        description: 'Application vulnerable to SQL injection or script injection attacks through client-side inputs.',
        impact: 'Data manipulation, unauthorized database access, and potential remote code execution.',
        location: 'DatabaseHelper.java:123 - SQL query construction',
        owasp: 'OWASP Mobile Top 10 2016 - M7'
    },
    {
        id: 'M10',
        title: 'Extraneous Functionality',
        severity: 'low',
        description: 'Hidden back-end functionality or debug features accessible in production builds.',
        impact: 'Potential backdoor access and unintended functionality exposure.',
        location: 'Debug menu accessible via specific gesture sequence',
        owasp: 'OWASP Mobile Top 10 2016 - M10'
    },
    {
        id: 'M6',
        title: 'Insecure Authorization',
        severity: 'low',
        description: 'Poor or missing authorization checks for accessing sensitive functionality.',
        impact: 'Users may access features or data beyond their authorized permissions.',
        location: 'AdminPanel.java - missing role validation',
        owasp: 'OWASP Mobile Top 10 2016 - M6'
    }
];

// Global variables
let scanProgress = 0;
let scanInterval;
let selectedFile = null;

// Scan process steps
const scanSteps = [
    'Extracting application package...',
    'Analyzing manifest file...',
    'Scanning for hardcoded secrets...',
    'Checking data storage mechanisms...',
    'Testing network communication...',
    'Validating authentication flows...',
    'Examining cryptographic implementations...',
    'Checking for code injection vulnerabilities...',
    'Analyzing authorization controls...',
    'Generating security report...'
];

/**
 * Initialize the application when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', function() {
    initializeFileHandling();
    initializeEventListeners();
});

/**
 * Initialize file upload handling
 */
function initializeFileHandling() {
    const fileUpload = document.getElementById('fileUpload');
    const fileInput = document.getElementById('fileInput');

    // Click handler for file upload area
    fileUpload.addEventListener('click', () => {
        fileInput.click();
    });

    // File selection handler
    fileInput.addEventListener('change', handleFileSelection);

    // Drag and drop handlers
    fileUpload.addEventListener('dragover', handleDragOver);
    fileUpload.addEventListener('dragleave', handleDragLeave);
    fileUpload.addEventListener('drop', handleFileDrop);
}

/**
 * Initialize other event listeners
 */
function initializeEventListeners() {
    // Add any additional event listeners here
    console.log('Mobile Security Assessment Tool initialized');
}

/**
 * Handle file selection from input
 */
function handleFileSelection(event) {
    const file = event.target.files[0];
    if (file) {
        processSelectedFile(file);
    }
}

/**
 * Handle drag over event
 */
function handleDragOver(event) {
    event.preventDefault();
    event.currentTarget.classList.add('dragover');
}

/**
 * Handle drag leave event
 */
function handleDragLeave(event) {
    event.currentTarget.classList.remove('dragover');
}

/**
 * Handle file drop event
 */
function handleFileDrop(event) {
    event.preventDefault();
    const fileUpload = event.currentTarget;
    fileUpload.classList.remove('dragover');
    
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        const file = files[0];
        if (isValidMobileAppFile(file)) {
            processSelectedFile(file);
            // Update the hidden file input
            const fileInput = document.getElementById('fileInput');
            fileInput.files = files;
        } else {
            showError('Please upload a valid mobile application file (.apk or .ipa)');
        }
    }
}

/**
 * Check if file is a valid mobile app file
 */
function isValidMobileAppFile(file) {
    const validExtensions = ['.apk', '.ipa'];
    const fileName = file.name.toLowerCase();
    return validExtensions.some(ext => fileName.endsWith(ext));
}

/**
 * Process the selected file and update UI
 */
function processSelectedFile(file) {
    selectedFile = file;
    const fileUpload = document.getElementById('fileUpload');
    
    fileUpload.innerHTML = `
        <i>✅</i>
        <p><strong>File Selected: ${file.name}</strong></p>
        <p>Size: ${(file.size / 1024 / 1024).toFixed(2)} MB</p>
        <p>Type: ${getFileType(file.name)}</p>
    `;
    fileUpload.style.background = '#e8f5e8';
    fileUpload.style.borderColor = '#27ae60';
}

/**
 * Get file type description
 */
function getFileType(fileName) {
    if (fileName.toLowerCase().endsWith('.apk')) {
        return 'Android Application Package';
    } else if (fileName.toLowerCase().endsWith('.ipa')) {
        return 'iOS Application Archive';
    }
    return 'Unknown';
}

/**
 * Start the security assessment scan
 */
function startScan() {
    const appName = document.getElementById('appName').value.trim();
    
    // Validation
    if (!appName) {
        showError('Please enter an application name');
        return;
    }
    
    if (!selectedFile) {
        showError('Please select a mobile application file');
        return;
    }

    // Hide main content and show scanning animation
    document.querySelector('.main-content').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'none';
    document.getElementById('scanningAnimation').style.display = 'block';

    // Initialize scan
    initializeScan();
}

/**
 * Initialize the scanning process
 */
function initializeScan() {
    scanProgress = 0;
    const progressFill = document.getElementById('progressFill');
    const scanStatus = document.getElementById('scanStatus');

    let currentStep = 0;
    
    scanInterval = setInterval(() => {
        scanProgress += 10;
        progressFill.style.width = scanProgress + '%';
        
        if (currentStep < scanSteps.length) {
            scanStatus.textContent = scanSteps[currentStep];
            currentStep++;
        }

        if (scanProgress >= 100) {
            clearInterval(scanInterval);
            setTimeout(() => {
                completeScan();
            }, 1000);
        }
    }, 800);
}

/**
 * Complete the scan and show results
 */
function completeScan() {
    document.getElementById('scanningAnimation').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'block';

    // Generate and display results
    displayScanResults();
    
    // Scroll to results
    document.getElementById('resultsPanel').scrollIntoView({ 
        behavior: 'smooth' 
    });
}

/**
 * Display the scan results
 */
function displayScanResults() {
    // Calculate statistics
    const highVulns = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumVulns = vulnerabilities.filter(v => v.severity === 'medium').length;
    const lowVulns = vulnerabilities.filter(v => v.severity === 'low').length;

    // Update statistics
    document.getElementById('highVulns').textContent = highVulns;
    document.getElementById('mediumVulns').textContent = mediumVulns;
    document.getElementById('lowVulns').textContent = lowVulns;
    document.getElementById('totalVulns').textContent = vulnerabilities.length;

    // Display vulnerability list
    displayVulnerabilityList();
}

/**
 * Display the list of vulnerabilities
 */
function displayVulnerabilityList() {
    const vulnerabilityList = document.getElementById('vulnerabilityList');
    vulnerabilityList.innerHTML = '';

    vulnerabilities.forEach((vuln, index) => {
        const vulnElement = createVulnerabilityElement(vuln, index);
        vulnerabilityList.appendChild(vulnElement);
    });
}

/**
 * Create a vulnerability element
 */
function createVulnerabilityElement(vuln, index) {
    const vulnElement = document.createElement('div');
    vulnElement.className = `vuln-item ${vuln.severity}`;
    vulnElement.style.animationDelay = `${index * 0.1}s`;
    
    vulnElement.innerHTML = `
        <div class="vuln-header">
            <div class="vuln-title">${vuln.id}: ${vuln.title}</div>
            <span class="severity-badge severity-${vuln.severity}">${vuln.severity.toUpperCase()}</span>
        </div>
        <div class="vuln-description">${vuln.description}</div>
        <div class="vuln-impact">
            <strong>Impact:</strong> ${vuln.impact}<br>
            <strong>Location:</strong> ${vuln.location}<br>
            <strong>Reference:</strong> ${vuln.owasp}
        </div>
    `;
    
    return vulnElement;
}

/**
 * Show error message
 */
function showError(message) {
    alert('Error: ' + message);
}

/**
 * Show success message
 */
function showSuccess(message) {
    alert('Success: ' + message);
}

/**
 * Export scan results as JSON
 */
function exportResults() {
    const appName = document.getElementById('appName').value;
    const platform = document.getElementById('platform').value;
    const scanDepth = document.getElementById('scanDepth').value;
    
    const report = {
        applicationInfo: {
            name: appName,
            platform: platform,
            fileName: selectedFile ? selectedFile.name : 'N/A',
            fileSize: selectedFile ? selectedFile.size : 0,
            scanDate: new Date().toISOString(),
            scanDepth: scanDepth
        },
        summary: {
            totalVulnerabilities: vulnerabilities.length,
            highRisk: vulnerabilities.filter(v => v.severity === 'high').length,
            mediumRisk: vulnerabilities.filter(v => v.severity === 'medium').length,
            lowRisk: vulnerabilities.filter(v => v.severity === 'low').length
        },
        vulnerabilities: vulnerabilities,
        methodology: 'OWASP Mobile Application Security Testing Guide (MASTG)',
        framework: 'OWASP Mobile Top 10 2016'
    };
    
    // Create and download JSON file
    const dataStr = JSON.stringify(report, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `security-assessment-${appName.replace(/\s+/g, '-')}-${new Date().getTime()}.json`;
    link.click();
    
    showSuccess('Security assessment report exported successfully!');
}

/**
 * Generate PDF report (simplified version)
 */
function generatePDFReport() {
    const appName = document.getElementById('appName').value;
    showSuccess(`PDF report for ${appName} would be generated here. This feature requires a PDF library integration.`);
}

/**
 * Reset the application to initial state
 */
function resetApplication() {
    // Reset form fields
    document.getElementById('appName').value = '';
    document.getElementById('platform').selectedIndex = 0;
    document.getElementById('scanDepth').selectedIndex = 1;
    
    // Reset file upload
    const fileUpload = document.getElementById('fileUpload');
    fileUpload.innerHTML = `
        <i>📱</i>
        <p><strong>Drop your mobile app file here</strong></p>
        <p>or click to browse</p>
        <p style="font-size: 0.9em; color: #666; margin-top: 10px;">Supported: .apk, .ipa files</p>
    `;
    fileUpload.style.background = '#fafafa';
    fileUpload.style.borderColor = '#ccc';
    
    document.getElementById('fileInput').value = '';
    selectedFile = null;
    
    // Hide results and show main content
    document.querySelector('.main-content').style.display = 'grid';
    document.getElementById('resultsPanel').style.display = 'none';
    document.getElementById('scanningAnimation').style.display = 'none';
    
    // Clear scan progress
    scanProgress = 0;
    if (scanInterval) {
        clearInterval(scanInterval);
    }
}

/**
 * Validate application configuration
 */
function validateConfiguration() {
    const appName = document.getElementById('appName').value.trim();
    const platform = document.getElementById('platform').value;
    const scanDepth = document.getElementById('scanDepth').value;
    
    const errors = [];
    
    if (!appName) {
        errors.push('Application name is required');
    }
    
    if (appName.length > 50) {
        errors.push('Application name must be less than 50 characters');
    }
    
    if (!selectedFile) {
        errors.push('Please select a mobile application file');
    }
    
    if (selectedFile && !isValidMobileAppFile(selectedFile)) {
        errors.push('Selected file must be a valid .apk or .ipa file');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

/**
 * Advanced scan options handler
 */
function handleAdvancedOptions() {
    const checkboxes = document.querySelectorAll('input[type="checkbox"]');
    const selectedTests = [];
    
    checkboxes.forEach(checkbox => {
        if (checkbox.checked) {
            selectedTests.push(checkbox.parentElement.textContent.trim());
        }
    });
    
    console.log('Selected security tests:', selectedTests);
    return selectedTests;
}

/**
 * Simulate real vulnerability scanning based on file type
 */
function simulateRealScan(fileName) {
    // Add platform-specific vulnerabilities based on file type
    if (fileName.toLowerCase().endsWith('.apk')) {
        return vulnerabilities.concat([
            {
                id: 'ANDROID-1',
                title: 'Android Manifest Misconfiguration',
                severity: 'medium',
                description: 'Android manifest contains insecure permissions or exported components.',
                impact: 'Potential privilege escalation and unauthorized access to app components.',
                location: 'AndroidManifest.xml - exported activities',
                owasp: 'Platform-specific Android vulnerability'
            }
        ]);
    } else if (fileName.toLowerCase().endsWith('.ipa')) {
        return vulnerabilities.concat([
            {
                id: 'IOS-1',
                title: 'iOS Info.plist Security Issues',
                severity: 'low',
                description: 'iOS Info.plist contains potentially insecure configurations.',
                impact: 'Information disclosure and potential security bypass.',
                location: 'Info.plist - NSAppTransportSecurity settings',
                owasp: 'Platform-specific iOS vulnerability'
            }
        ]);
    }
    
    return vulnerabilities;
}

/**
 * Generate detailed security recommendations
 */
function generateRecommendations() {
    const recommendations = [
        {
            category: 'Data Protection',
            items: [
                'Implement proper encryption for sensitive data storage',
                'Use Android Keystore or iOS Keychain for credential storage',
                'Avoid storing sensitive data in shared preferences or plists'
            ]
        },
        {
            category: 'Network Security',
            items: [
                'Implement certificate pinning for critical connections',
                'Use TLS 1.2 or higher for all network communications',
                'Validate all server certificates properly'
            ]
        },
        {
            category: 'Authentication & Authorization',
            items: [
                'Implement multi-factor authentication where possible',
                'Use secure session management techniques',
                'Implement proper role-based access controls'
            ]
        },
        {
            category: 'Code Protection',
            items: [
                'Implement code obfuscation for sensitive algorithms',
                'Remove all debug code and logging in production',
                'Use runtime application self-protection (RASP)'
            ]
        }
    ];
    
    return recommendations;
}

/**
 * Create and display recommendations panel
 */
function showRecommendations() {
    const recommendations = generateRecommendations();
    let recommendationsHTML = '<h3>🛡️ Security Recommendations</h3>';
    
    recommendations.forEach(category => {
        recommendationsHTML += `
            <div style="margin: 15px 0;">
                <h4 style="color: #2c3e50; margin-bottom: 10px;">${category.category}</h4>
                <ul style="margin-left: 20px;">
        `;
        
        category.items.forEach(item => {
            recommendationsHTML += `<li style="margin: 5px 0; color: #666;">${item}</li>`;
        });
        
        recommendationsHTML += '</ul></div>';
    });
    
    // Add recommendations to results panel
    const resultsPanel = document.getElementById('resultsPanel');
    const recommendationsDiv = document.createElement('div');
    recommendationsDiv.innerHTML = recommendationsHTML;
    recommendationsDiv.style.background = '#f8f9fa';
    recommendationsDiv.style.padding = '20px';
    recommendationsDiv.style.borderRadius = '10px';
    recommendationsDiv.style.marginTop = '20px';
    
    resultsPanel.appendChild(recommendationsDiv);
}

/**
 * Handle keyboard shortcuts
 */
document.addEventListener('keydown', function(event) {
    // Ctrl/Cmd + R: Reset application
    if ((event.ctrlKey || event.metaKey) && event.key === 'r') {
        event.preventDefault();
        if (confirm('Are you sure you want to reset the application?')) {
            resetApplication();
        }
    }
    
    // Ctrl/Cmd + E: Export results (if results are visible)
    if ((event.ctrlKey || event.metaKey) && event.key === 'e') {
        const resultsPanel = document.getElementById('resultsPanel');
        if (resultsPanel.style.display !== 'none') {
            event.preventDefault();
            exportResults();
        }
    }
});

/**
 * Add security tips and best practices
 */
const securityTips = [
    "Always test your applications on both rooted and non-rooted devices",
    "Implement proper SSL certificate validation and pinning",
    "Never store sensitive data in plain text or reversible encryption",
    "Use the principle of least privilege for app permissions",
    "Implement proper session management and timeout mechanisms",
    "Regularly update and patch third-party libraries and dependencies",
    "Implement proper input validation to prevent injection attacks",
    "Use secure communication protocols (HTTPS/TLS) for all network traffic"
];

/**
 * Display random security tip
 */
function showSecurityTip() {
    const randomTip = securityTips[Math.floor(Math.random() * securityTips.length)];
    const tipElement = document.createElement('div');
    tipElement.innerHTML = `
        <div style="background: linear-gradient(135deg, #3498db, #2c3e50); color: white; padding: 15px; border-radius: 10px; margin: 20px 0;">
            <strong>💡 Security Tip:</strong> ${randomTip}
        </div>
    `;
    
    const container = document.querySelector('.container');
    container.appendChild(tipElement);
    
    // Remove tip after 5 seconds
    setTimeout(() => {
        tipElement.remove();
    }, 5000);
}

// Show a security tip when the page loads
window.addEventListener('load', function() {
    setTimeout(showSecurityTip, 2000);
});

// Export functions for potential external use
window.MobSecScan = {
    startScan,
    resetApplication,
    exportResults,
    showRecommendations,
    validateConfiguration
};