// =====================================
// Phishing URL Detector
// SCRIPT.JS
// =====================================

// DOM Elements

const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const themeToggle = document.getElementById("themeToggle");

const riskScore = document.getElementById("riskScore");
const statusText = document.getElementById("statusText");
const analysisText = document.getElementById("analysisText");

const urlDisplay = document.getElementById("urlDisplay");
const protocolDisplay = document.getElementById("protocolDisplay");
const scanTime = document.getElementById("scanTime");

const analysisList = document.getElementById("analysisList");
const historyContainer = document.getElementById("historyContainer");

const totalScans = document.getElementById("totalScans");
const safeCount = document.getElementById("safeCount");
const warningCount = document.getElementById("warningCount");
const dangerCount = document.getElementById("dangerCount");

// =====================================
// LOCAL STORAGE KEYS
// =====================================

const HISTORY_KEY = "phishguard_history";
const THEME_KEY = "phishguard_theme";

// =====================================
// LOAD APP
// =====================================

window.addEventListener("DOMContentLoaded", () => {
    loadTheme();
    renderHistory();
    updateStats();
});

// =====================================
// THEME TOGGLE
// =====================================

themeToggle.addEventListener("click", () => {

    document.body.classList.toggle("light-mode");

    const theme = document.body.classList.contains("light-mode")
        ? "light"
        : "dark";

    localStorage.setItem(THEME_KEY, theme);
});

function loadTheme() {

    const savedTheme = localStorage.getItem(THEME_KEY);

    if(savedTheme === "light"){
        document.body.classList.add("light-mode");
    }
}

// =====================================
// SCAN BUTTON
// =====================================

scanBtn.addEventListener("click", scanURL);

// =====================================
// VALIDATE URL
// =====================================

function isValidURL(url){

    try{
        new URL(url);
        return true;
    }
    catch{
        return false;
    }
}

// =====================================
// MAIN SCAN
// =====================================

function scanURL(){

    const url = urlInput.value.trim();

    if(url === ""){
        showAlert("Please enter a URL");
        return;
    }

    if(!isValidURL(url)){
        showAlert("Invalid URL format");
        return;
    }

    const result = analyzeURL(url);

    updateUI(url,result);

    saveHistory(url,result);

    renderHistory();

    updateStats();
}

// =====================================
// ANALYSIS ENGINE
// =====================================

function analyzeURL(url){

    let score = 0;
    let warnings = [];

    const lowerURL = url.toLowerCase();

    // HTTPS CHECK

    if(url.startsWith("http://")){
        score += 20;

        warnings.push(
            "Website is not using HTTPS"
        );
    }

    // SUSPICIOUS WORDS

    const suspiciousWords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "account",
        "signin",
        "confirm",
        "paypal",
        "wallet"
    ];

    suspiciousWords.forEach(word => {

        if(lowerURL.includes(word)){

            score += 8;

            warnings.push(
                `Contains suspicious keyword: ${word}`
            );
        }
    });

    // @ SYMBOL

    if(url.includes("@")){

        score += 15;

        warnings.push(
            "Contains @ symbol"
        );
    }

    // LONG URL

    if(url.length > 75){

        score += 15;

        warnings.push(
            "URL is unusually long"
        );
    }

    // MANY SUBDOMAINS

    const domainParts = new URL(url)
        .hostname
        .split(".");

    if(domainParts.length > 4){

        score += 15;

        warnings.push(
            "Too many subdomains"
        );
    }

    // IP ADDRESS CHECK

    const ipRegex =
        /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

    if(ipRegex.test(url)){

        score += 25;

        warnings.push(
            "Uses IP address instead of domain"
        );
    }

    // TLD CHECK

    const suspiciousTlds = [
        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ];

    suspiciousTlds.forEach(tld => {

        if(lowerURL.includes(tld)){

            score += 10;

            warnings.push(
                `Suspicious domain extension (${tld})`
            );
        }
    });

    // STATUS

    let status = "SAFE";

    if(score >= 60){
        status = "DANGER";
    }
    else if(score >= 30){
        status = "WARNING";
    }

    return {
        score,
        status,
        warnings
    };
}

// =====================================
// UPDATE UI
// =====================================

function updateUI(url,result){

    riskScore.textContent = result.score;

    statusText.textContent = result.status;

    analysisText.textContent =
        result.warnings.length > 0
        ? `${result.warnings.length} warnings detected`
        : "No suspicious indicators found";

    urlDisplay.textContent = url;

    protocolDisplay.textContent =
        url.startsWith("https")
        ? "HTTPS"
        : "HTTP";

    scanTime.textContent =
        new Date().toLocaleString();

    renderWarnings(result.warnings);

    updateStatusColor(result.status);
}

// =====================================
// STATUS COLOR
// =====================================

function updateStatusColor(status){

    statusText.style.color = "";

    if(status === "SAFE"){
        statusText.style.color = "#00ffae";
    }

    if(status === "WARNING"){
        statusText.style.color = "#ffb347";
    }

    if(status === "DANGER"){
        statusText.style.color = "#ff4b4b";
    }
}

// =====================================
// WARNINGS
// =====================================

function renderWarnings(warnings){

    if(warnings.length === 0){

        analysisList.innerHTML = `
            <div class="analysis-empty">
                <h3 style="color:#00ffae">
                    URL Looks Safe
                </h3>
            </div>
        `;

        return;
    }

    let html = "";

    warnings.forEach(item => {

        html += `
            <div class="warning-item"
                 style="
                 margin-bottom:10px;
                 padding:15px;
                 border-radius:12px;
                 border:1px solid rgba(255,75,75,.2);
                 background:rgba(255,75,75,.05);">

                 ⚠ ${item}
            </div>
        `;
    });

    analysisList.innerHTML = html;
}

// =====================================
// HISTORY
// =====================================

function saveHistory(url,result){

    const history =
        JSON.parse(
            localStorage.getItem(HISTORY_KEY)
        ) || [];

    history.unshift({

        url,
        score: result.score,
        status: result.status,

        date:
            new Date()
            .toLocaleString()
    });

    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history)
    );
}

// =====================================
// HISTORY UI
// =====================================

function renderHistory(){

    const history =
        JSON.parse(
            localStorage.getItem(HISTORY_KEY)
        ) || [];

    if(history.length === 0){

        historyContainer.innerHTML = `
        <div class="history-empty">
            <i class="fa-solid fa-box-open"></i>
            <p>No history yet</p>
        </div>
        `;

        return;
    }

    let html = "";

    history.forEach((item,index)=>{

        html += `
        <div
        style="
        border:1px solid rgba(255,255,255,.05);
        padding:15px;
        border-radius:15px;
        margin-bottom:10px;
        background:rgba(255,255,255,.02);">

            <strong>${item.status}</strong>

            <p style="
            margin-top:8px;
            word-break:break-all;">
                ${item.url}
            </p>

            <small>
                ${item.date}
            </small>

            <br><br>

            <button
            onclick="deleteHistory(${index})"
            style="
            background:#ff4b4b;
            border:none;
            color:white;
            padding:8px 12px;
            border-radius:8px;
            cursor:pointer;">

            Delete
            </button>

        </div>
        `;
    });

    historyContainer.innerHTML = html;
}

// =====================================
// DELETE HISTORY
// =====================================

function deleteHistory(index){

    const history =
        JSON.parse(
            localStorage.getItem(HISTORY_KEY)
        ) || [];

    history.splice(index,1);

    localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(history)
    );

    renderHistory();

    updateStats();
}

// =====================================
// STATISTICS
// =====================================

function updateStats(){

    const history =
        JSON.parse(
            localStorage.getItem(HISTORY_KEY)
        ) || [];

    totalScans.textContent =
        history.length;

    safeCount.textContent =
        history.filter(
            item => item.status==="SAFE"
        ).length;

    warningCount.textContent =
        history.filter(
            item => item.status==="WARNING"
        ).length;

    dangerCount.textContent =
        history.filter(
            item => item.status==="DANGER"
        ).length;
}

// =====================================
// COPY REPORT
// =====================================

function copyReport(){

    const report = `
URL: ${urlDisplay.textContent}
Status: ${statusText.textContent}
Risk Score: ${riskScore.textContent}
Time: ${scanTime.textContent}
`;

    navigator.clipboard.writeText(report);

    showAlert("Report copied");
}

// =====================================
// EXPORT TXT
// =====================================

function exportTXT(){

    const report = `
Phishing URL Detector REPORT

URL:
${urlDisplay.textContent}

STATUS:
${statusText.textContent}

RISK SCORE:
${riskScore.textContent}

TIME:
${scanTime.textContent}
`;

    const blob =
        new Blob([report],
        {type:"text/plain"});

    const link =
        document.createElement("a");

    link.href =
        URL.createObjectURL(blob);

    link.download =
        "phishguard-report.txt";

    link.click();
}

// =====================================
// ALERT
// =====================================

function showAlert(message){

    alert(message);
}

// =====================================
// GLOBAL FUNCTIONS
// =====================================

window.deleteHistory =
    deleteHistory;

window.copyReport =
    copyReport;

window.exportTXT =
    exportTXT;