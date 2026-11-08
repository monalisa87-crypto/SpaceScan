
const $ = id => document.getElementById(id);

const esc = value =>
    String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[char]));

// ==========================================
// 1. LOCAL STORAGE
// ==========================================

let reports = [];
let history = [];

try {
    reports = JSON.parse(localStorage.getItem("spacescan-reports") || "[]");
    history = JSON.parse(localStorage.getItem("spacescan-history") || "[]");

    if (!Array.isArray(reports)) reports = [];
    if (!Array.isArray(history)) history = [];
} catch {
    reports = [];
    history = [];
}

function saveData() {
    localStorage.setItem("spacescan-reports", JSON.stringify(reports));
    localStorage.setItem("spacescan-history", JSON.stringify(history));
}

// ==========================================
// 2. URL VALIDATION
// ==========================================

function parseAddress(value) {
    const raw = String(value || "").trim();

    if (!raw || /\s/.test(raw)) return null;

    // Reject incomplete or unsupported schemes.
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw) &&
        !/^https?:\/\//i.test(raw)) {
        return null;
    }

    // Require a proper HTTP or HTTPS address.
    const address = /^https?:\/\//i.test(raw)
        ? raw
        : "https://" + raw;

    try {
        const url = new URL(address);

        if (!["http:", "https:"].includes(url.protocol)) return null;
        if (!url.hostname || url.username || url.password) return null;

        const host = url.hostname.toLowerCase();

        if (host.length > 253) return null;

        // Localhost
        if (host === "localhost") return url;

        // IPv4
        const ipv4 = host.split(".");

        const isIPv4 =
            ipv4.length === 4 &&
            ipv4.every(part =>
                /^\d{1,3}$/.test(part) &&
                Number(part) >= 0 &&
                Number(part) <= 255
            );

        if (isIPv4) return url;

        // IPv6
        if (host.startsWith("[") && host.endsWith("]")) {
            return url;
        }

        // Domain validation
        const labels = host.split(".");

        if (labels.length < 2) return null;

        const validLabels = labels.every(label =>
            label.length >= 1 &&
            label.length <= 63 &&
            /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
        );

        if (!validLabels) return null;

        const tld = labels[labels.length - 1];

        const validTLD =
            /^[a-z]{2,63}$/i.test(tld) ||
            /^xn--[a-z0-9-]{2,59}$/i.test(tld);

        if (!validTLD) return null;

        return url;

    } catch {
        return null;
    }
}

function hostOf(value) {
    return parseAddress(value)?.hostname.toLowerCase() || "";
}

// ==========================================
// 3. STATUS HELPERS
// ==========================================

const BADGE = {
    pass: "Clear",
    warn: "Caution",
    fail: "Risk",
    unknown: "Not checked"
};

function item(label, status, detail) {
    return { label, status, detail };
}

// ==========================================
// 4. URL RISK DETECTION
// ==========================================

function scan(raw) {
    const url = parseAddress(raw);

    if (!url) {
        throw new Error("Invalid website address.");
    }

    const host = url.hostname.toLowerCase();

    const usesHTTP = url.protocol === "http:";

    const isIP =
        /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
        (host.startsWith("[") && host.endsWith("]"));

    const suspiciousTLD =
        /\.(xyz|top|click|zip|work|buzz|live|gq|tk|ml)$/i.test(host);

    const suspiciousWords = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "bank",
        "pay",
        "wallet",
        "confirm"
    ];

    const foundWords = suspiciousWords.filter(word =>
        host.split(/[.-]/).includes(word)
    );

    const hyphens = (host.match(/-/g) || []).length;

    const threat = [];

    // HTTP / HTTPS
    threat.push(
        item(
            "Address scheme",
            usesHTTP ? "warn" : "pass",
            usesHTTP
                ? "This website uses HTTP instead of HTTPS."
                : "The address uses HTTPS, but the connection has not been independently verified."
        )
    );

    // IP address
    threat.push(
        item(
            "Address format",
            isIP ? "warn" : "pass",
            isIP
                ? "This website uses a direct IP address."
                : "A domain name is present."
        )
    );

    // Domain ending
    threat.push(
        item(
            "Domain ending",
            suspiciousTLD ? "warn" : "pass",
            suspiciousTLD
                ? "This domain ending deserves extra caution."
                : "No flagged domain ending found in the local list."
        )
    );

    // Suspicious words
    threat.push(
        item(
            "Words in domain",
            foundWords.length ? "warn" : "pass",
            foundWords.length
                ? "Potentially misleading terms: " + foundWords.join(", ")
                : "No common login or payment bait terms found."
        )
    );

    // Hyphens and length
    threat.push(
        item(
            "Hyphens and length",
            hyphens >= 2 || raw.length > 75 ? "warn" : "pass",
            `${hyphens} hyphen(s); ${raw.length} characters.`
        )
    );

    // Credentials
    threat.push(
        item(
            "Embedded credentials",
            url.username || url.password ? "fail" : "pass",
            url.username || url.password
                ? "The address contains embedded login credentials."
                : "No embedded username or password found."
        )
    );

    // ======================================
    // 5. COMMUNITY REPORT CHECK
    // ======================================

    const matchingReports = reports.filter(report =>
        report.host === host
    );

    const intel = [
        item(
            "Community reports",
            matchingReports.length ? "warn" : "pass",
            matchingReports.length
                ? `${matchingReports.length} report(s) saved for this domain in this browser.`
                : "No reports saved locally for this domain."
        )
    ];

    // ======================================
    // 6. SECURITY & CERTIFICATE
    // ======================================

    const security = [
        item(
            "Live security check",
            "unknown",
            "Live DNS, redirects, security headers and reputation checks are not connected yet."
        )
    ];

    const certificate = [
        item(
            "SSL certificate",
            "unknown",
            "Certificate issuer, expiry and domain identity have not been verified by the backend."
        )
    ];

    // ======================================
    // 7. RISK SCORE
    // ======================================

    const points = {
        pass: 0,
        warn: 12,
        fail: 25
    };

    const score = Math.min(
        100,
        [...threat, ...intel].reduce(
            (total, result) =>
                total + (points[result.status] || 0),
            0
        )
    );

    return {
        score,
        threat,
        security,
        certificate,
        intel
    };
}

// ==========================================
// 8. RISK VERDICT
// ==========================================

function level(score) {

    if (score < 20) {
        return {
            name: "Few URL warnings",
            color: "var(--safe)",
            text: "Few suspicious URL patterns were detected. This does not guarantee safety."
        };
    }

    if (score < 50) {
        return {
            name: "Use caution",
            color: "var(--warn)",
            text: "Some suspicious URL patterns were detected. Verify the website before sharing information."
        };
    }

    return {
        name: "High URL warning score",
        color: "var(--bad)",
        text: "Several suspicious URL patterns were detected. Avoid entering sensitive information."
    };
}

// ==========================================
// 9. DISPLAY SCAN RESULTS
// ==========================================

const SECTIONS = [
    ["threat", "URL Clues", "Patterns visible in the address"],
    ["security", "Web Security", "Live connection checks"],
    ["certificate", "Certificate", "Website identity checks"],
    ["intel", "Community Reports", "Reports saved in this browser"]
];

function render(data, rawURL) {

    const verdict = level(data.score);

    $("score").textContent = data.score;

    $("verdict").textContent = verdict.name;
    $("verdict").style.color = verdict.color;

    $("verdictText").textContent =
        verdict.text + " (" + rawURL + ")";

    // Gauge
    const arc = $("arc");

    arc.setAttribute("stroke", verdict.color);
    arc.setAttribute("stroke-dasharray", "0 100");

    requestAnimationFrame(() => {
        arc.setAttribute(
            "stroke-dasharray",
            `${data.score} 100`
        );
    });

    // Result cards
    $("cards").innerHTML = SECTIONS.map(
        ([key, title, subtitle]) => `
            <article class="card">

                <h3>${title}</h3>
                <p class="sub">${subtitle}</p>

                <ul>
                    ${(data[key] || []).map(result => `
                        <li>

                            <span class="badge ${esc(result.status)}">
                                ${BADGE[result.status]}
                            </span>

                            <div>
                                <b>${esc(result.label)}</b>
                                <span class="d">
                                    ${esc(result.detail)}
                                </span>
                            </div>

                        </li>
                    `).join("")}
                </ul>

            </article>
        `
    ).join("");

    $("result").style.display = "block";
}

// ==========================================
// 10. SCAN HISTORY
// ==========================================

function renderHistory() {

    const container = $("scanHistory");

    if (!container) return;

    if (!history.length) {
        container.innerHTML =
            '<p>No previous scans displayed yet.</p>';
        return;
    }

    container.innerHTML = history.slice(0, 8).map(entry => `
        <div class="history-item">

            <div>
                <b>${esc(entry.host)}</b>
                <small>${esc(entry.date)}</small>
            </div>

            <span class="history-score">
                Score: ${entry.score}/100
            </span>

        </div>
    `).join("");
}

function addHistory(host, score) {

    history.unshift({
        host,
        score,
        date: new Date().toLocaleString()
    });

    history = history.slice(0, 20);

    saveData();
    renderHistory();
}

// ==========================================
// 11. MAIN SCAN BUTTON
// ==========================================

$("scanForm").addEventListener("submit", async event => {

    event.preventDefault();

    const input = $("url");
    const rawURL = input.value.trim();

    const status = $("status");
    const button = $("scanBtn");

    // Validate format
    if (!parseAddress(rawURL)) {

        status.textContent =
            "Invalid URL format! Enter a valid domain such as example.com or https://example.com.";

        status.classList.add("error");

        input.setAttribute("aria-invalid", "true");

        $("result").style.display = "none";

        input.focus();

        return;
    }

    input.removeAttribute("aria-invalid");

    status.classList.remove("error");

    button.disabled = true;
    button.textContent = "Scanning...";

    status.textContent = "Checking URL patterns...";

    $("result").style.display = "none";

    try {

        const data = scan(rawURL);

        render(data, rawURL);

        addHistory(
            parseAddress(rawURL).hostname,
            data.score
        );

        status.textContent =
            "Local URL review completed. Live checks are not connected.";

        $("result").scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    } catch (error) {

        status.textContent =
            "Scan failed: " + error.message;

        status.classList.add("error");

    } finally {

        button.disabled = false;
        button.textContent = "Scan Website";
    }
});

// ==========================================
// 12. EXAMPLE URL BUTTONS
// ==========================================

document.querySelectorAll("[data-url]").forEach(button => {

    button.addEventListener("click", () => {

        $("url").value = button.dataset.url;

        $("scanForm").requestSubmit();
    });

});

// ==========================================
// 13. COMMUNITY REPORTS
// ==========================================

function renderReports() {

    const list = $("reports");

    if (!reports.length) {

        list.innerHTML =
            '<li class="empty">No reports yet. Be the first to report a site.</li>';

        return;
    }

    list.innerHTML = reports.slice(0, 8).map(report => `
        <li>

            <b>${esc(report.host)}</b>

            <small>
                ${esc(report.type)} · ${esc(report.when)}
            </small>

        </li>
    `).join("");
}

// ==========================================
// 14. SUBMIT REPORT
// ==========================================

$("reportForm").addEventListener("submit", event => {

    event.preventDefault();

    const host = hostOf($("rUrl").value.trim());

    if (!host) {

        alert("Invalid website address. Please enter a valid domain.");

        $("rUrl").focus();

        return;
    }

    reports.unshift({

        host,
        type: $("rType").value,
        note: $("rNote").value.trim(),
        when: new Date().toLocaleDateString()

    });

    saveData();

    renderReports();

    $("reportForm").reset();

    alert("Your report has been saved successfully!");
});

// ==========================================
// 15. INITIALIZE SPACESCAN
// ==========================================

renderReports();
renderHistory();
