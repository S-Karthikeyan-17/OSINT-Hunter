document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const form = document.getElementById("reconForm");
  const targetInput = document.getElementById("targetInput");
  const authInput = document.getElementById("authInput");
  const wordlistInput = document.getElementById("wordlistInput");
  const spiderfootCheckbox = document.getElementById("spiderfootCheckbox");
  const resultsDiv = document.getElementById("results");
  const authToggleBtn = document.getElementById("authToggleBtn");
  const authToggleIcon = document.getElementById("authToggleIcon");
  const connectionStatus = document.getElementById("connectionStatus");
  const scanStatus = document.getElementById("scanStatus");

  // Initialize theme (dark theme only)
  document.documentElement.setAttribute("data-theme", "dark");

  // Initialize auth key from localStorage
  const storedKey = localStorage.getItem("recon_auth_key");
  if (storedKey && authInput) authInput.value = storedKey;

  // Matrix rain effect
  function initMatrixEffect() {
    const canvas = document.getElementById("matrixCanvas");
    if (!canvas) {
      console.warn("Matrix canvas not found. Ensure <canvas id='matrixCanvas' class='matrix-bg'></canvas> exists in HTML.");
      return;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) {
      console.error("Failed to get 2D context for canvas.");
      return;
    }

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン@#$%^&*()_+-=[]{}|;:,.<>?";
    const charArray = chars.split("");
    const baseFontSize = 15;
    const columns = Math.floor(canvas.width / (baseFontSize * 0.6));
    const drops = Array(columns).fill(1);

    const colors = [
      getComputedStyle(document.documentElement).getPropertyValue("--primary-color").trim() || "#00ff9f",
      getComputedStyle(document.documentElement).getPropertyValue("--accent-color").trim() || "#ff00a0",
      getComputedStyle(document.documentElement).getPropertyValue("--secondary-color").trim() || "#1bc7ff"
    ];

    function draw() {
      ctx.fillStyle = "rgba(0, 0, 0, 0.1)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      drops.forEach((drop, index) => {
        const text = charArray[Math.floor(Math.random() * charArray.length)];
        const color = colors[Math.floor(Math.random() * colors.length)];
        const size = baseFontSize + Math.random() * 3;
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.6 + 0.4 * Math.sin(Date.now() / 300 + index);
        ctx.font = `${size}px 'JetBrains Mono', monospace`;
        ctx.fillText(text, index * (baseFontSize * 0.6), drop * size);

        if (drop * size > canvas.height && Math.random() > 0.98) {
          drops[index] = 0;
        }
        drops[index] += 0.5 + Math.random() * 0.3;
      });
      ctx.globalAlpha = 1;
    }

    setInterval(draw, 25);

    // Debounced resize handler
    let resizeTimeout;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        drops.length = Math.floor(canvas.width / (baseFontSize * 0.6));
        drops.fill(1);
      }, 100);
    });
  }

  // Toggle password visibility
  if (authToggleBtn && authInput && authToggleIcon) {
    authToggleBtn.addEventListener("click", () => {
      authInput.type = authInput.type === "password" ? "text" : "password";
      authToggleIcon.textContent = authInput.type === "password" ? "👁️" : "🙈";
    });
  } else {
    console.warn("Auth toggle elements not found.");
  }

  // Form enhancements
  function initFormEnhancements() {
    const inputs = document.querySelectorAll(".cyber-input");
    inputs.forEach(input => {
      if (input.value) input.parentNode.classList.add("focused");
      input.addEventListener("focus", () => input.parentNode.classList.add("focused"));
      input.addEventListener("blur", () => {
        if (!input.value) input.parentNode.classList.remove("focused");
      });
    });

    if (form) {
      form.addEventListener("submit", (e) => {
        const submitButton = form.querySelector("button[type='submit']");
        if (submitButton) submitButton.classList.add("loading");
        if (connectionStatus) {
          connectionStatus.innerHTML = `<div class="pulse active"></div><span>Scanning...</span>`;
        }
        if (scanStatus) scanStatus.textContent = "Scanning";
      });
    }
  }

  // Notification system
  function showNotification(message, type = "success") {
    const notification = document.createElement("div");
    notification.className = `notification ${type}`;
    notification.innerHTML = `<span>${type === "success" ? "✅" : "⚠️"}</span>${escapeHtml(message)}`;
    document.body.appendChild(notification);
    setTimeout(() => {
      notification.style.opacity = "0";
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }

  // Export results
  window.exportResults = function () {
    if (!resultsDiv) return;
    const results = resultsDiv.innerHTML;
    if (results.includes("Reconnaissance results will appear here")) {
      showNotification("No results to export.", "error");
      return;
    }
    const blob = new Blob([results], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `recon_results_${new Date().toISOString()}.html`;
    a.click();
    URL.revokeObjectURL(url);
    showNotification("Results exported successfully!", "success");
  };

  // Clear results
  window.clearResults = function () {
    if (resultsDiv) {
      resultsDiv.innerHTML = `
        <div class="placeholder">
          <div class="placeholder-icon">⏳</div>
          <p>Reconnaissance results will appear here...</p>
          <div class="scan-animation"></div>
        </div>
      `;
      showNotification("Results cleared.", "success");
    }
  };

  // Form submission handler
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const submitButton = form.querySelector("button[type='submit']");
      const target = targetInput?.value.trim();
      const auth = authInput?.value.trim();
      const wordlist = wordlistInput?.value.trim();
      const useSpiderfoot = spiderfootCheckbox?.checked ? "1" : "0";
      const backendHost = "http://127.0.0.1:5000";

      // Validate domain
      if (!target || !/^[a-zA-Z0-9][a-zA-Z0-9.-]{1,253}[a-zA-Z0-9]$/.test(target)) {
        if (resultsDiv) resultsDiv.innerHTML = `<div class="error">❌ Please enter a valid domain (e.g., example.com).</div>`;
        if (submitButton) submitButton.classList.remove("loading");
        if (connectionStatus) connectionStatus.innerHTML = `<div class="pulse"></div><span>Ready</span>`;
        if (scanStatus) scanStatus.textContent = "Idle";
        showNotification("Please enter a valid domain.", "error");
        return;
      }

      if (!auth) {
        if (resultsDiv) resultsDiv.innerHTML = `<div class="error">❌ Please enter an auth key.</div>`;
        if (submitButton) submitButton.classList.remove("loading");
        if (connectionStatus) connectionStatus.innerHTML = `<div class="pulse"></div><span>Ready</span>`;
        if (scanStatus) scanStatus.textContent = "Idle";
        showNotification("Please enter an auth key.", "error");
        return;
      }

      localStorage.setItem("recon_auth_key", auth);
      if (resultsDiv) resultsDiv.innerHTML = `<div class="loading">🔍 Running reconnaissance on <strong>${escapeHtml(target)}</strong>...</div>`;
      if (scanStatus) scanStatus.textContent = "Scanning";

      try {
        let url = `${backendHost.replace(/\/+$/, "")}/api/recon?target=${encodeURIComponent(target)}&use_spiderfoot=${useSpiderfoot}`;
        if (wordlist) url += `&wordlist=${encodeURIComponent(wordlist)}`;

        const response = await fetch(url, {
          method: "GET",
          headers: { "X-RECON-AUTH": auth, "Accept": "application/json" }
        });

        if (!response.ok) {
          let errBody = "";
          try {
            const txt = await response.text();
            try {
              const j = JSON.parse(txt);
              errBody = j.error ? ` - ${j.error}` : ` - ${txt}`;
            } catch {
              errBody = txt ? ` - ${txt}` : "";
            }
          } catch {
            errBody = "";
          }
          let message;
          if (response.status === 403) {
            message = `403 Forbidden: Authorization failed${errBody}.`;
          } else if (response.status === 429) {
            message = `429 Too Many Requests: Rate limit exceeded${errBody}.`;
          } else if (!navigator.onLine) {
            message = "Network error: You are offline.";
          } else {
            message = `${response.status} ${response.statusText}${errBody}`;
          }
          throw new Error(message);
        }

        const data = await response.json();
        if (data.error) throw new Error(data.error);

        if (resultsDiv) resultsDiv.innerHTML = renderResults(data.result || data);
        if (submitButton) submitButton.classList.remove("loading");
        if (connectionStatus) connectionStatus.innerHTML = `<div class="pulse"></div><span>Ready</span>`;
        if (scanStatus) scanStatus.textContent = "Complete";
        showNotification("Reconnaissance completed successfully!", "success");
      } catch (err) {
        if (resultsDiv) resultsDiv.innerHTML = `<div class="error">❌ Error: ${escapeHtml(err.message)}.</div>`;
        console.error("Recon error:", err);
        if (submitButton) submitButton.classList.remove("loading");
        if (connectionStatus) connectionStatus.innerHTML = `<div class="pulse"></div><span>Ready</span>`;
        if (scanStatus) scanStatus.textContent = "Failed";
        showNotification(`Reconnaissance failed: ${err.message}`, "error");
      }
    });
  }

  // Render results with accordions and CVE chart
  function renderResults(data) {
    if (!data) return `<div class="error">No data returned.</div>`;
    let html = `<h3 class="holographic">📊 Recon Results for ${escapeHtml(data.target || "")}</h3>`;

    // Summary Card
    if (data.summary) {
      const spiderfootStatus = data.summary.spiderfoot_status || (
        Array.isArray(data.spiderfoot_events) && data.spiderfoot_events.length > 0
          ? data.spiderfoot_events[0]?.status || "Not run"
          : "Not run"
      );
      html += `
        <div class="data-card">
          <h4 class="holographic">Summary</h4>
          <div class="data-stat"><span class="stat-label">Subdomains Found</span><span class="stat-value">${data.summary.num_subdomains || 0}</span></div>
          <div class="data-stat"><span class="stat-label">Hosts Scanned</span><span class="stat-value">${data.summary.num_hosts || 0}</span></div>
          <div class="data-stat"><span class="stat-label">Emails Discovered</span><span class="stat-value">${data.summary.num_emails || 0}</span></div>
          <div class="data-stat"><span class="stat-label">GitHub Hits</span><span class="stat-value">${data.summary.github_hits || 0}</span></div>
          <div class="data-stat"><span class="stat-label">Pastebin Hits</span><span class="stat-value">${data.summary.paste_hits || 0}</span></div>
          <div class="data-stat"><span class="stat-label">SpiderFoot Status</span><span class="stat-value">${escapeHtml(spiderfootStatus)}</span></div>
        </div>
      `;
    }

    // Subdomains
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="subdomains-content">Subdomains (${data.subdomains?.length || 0})</button>
      <div class="accordion-content" id="subdomains-content">
        <ul>${data.subdomains?.map(s => `<li>${escapeHtml(s)}</li>`).join("") || "<li>No subdomains found.</li>"}</ul>
      </div>
    </div>`;

    // Hosts
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="hosts-content">Hosts (${data.hosts?.length || 0})</button>
      <div class="accordion-content" id="hosts-content">
        <table>
          <thead><tr><th>Hostname</th><th>IPs</th><th>Open Ports</th><th>Services</th><th>Nmap Ports</th></tr></thead>
          <tbody>${data.hosts?.map(h => `
            <tr>
              <td>${escapeHtml(h.hostname || "")}</td>
              <td>${h.ips?.map(ip => escapeHtml(ip)).join(", ") || "N/A"}</td>
              <td>${h.open_ports?.join(", ") || "None"}</td>
              <td>${h.services?.map(s => escapeHtml(s)).join("; ") || "None"}</td>
              <td>${h.nmap_ports?.join(", ") || "N/A"}</td>
            </tr>`).join("") || "<tr><td colspan='5'>No hosts found.</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>`;

    // WHOIS
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="whois-content">WHOIS</button>
      <div class="accordion-content" id="whois-content">
        <pre>${escapeHtml(JSON.stringify(data.whois || {}, null, 2))}</pre>
      </div>
    </div>`;

    // Tech Stack
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="tech-content">Tech Stack</button>
      <div class="accordion-content" id="tech-content">
        <pre>${escapeHtml(JSON.stringify(data.tech || {}, null, 2))}</pre>
      </div>
    </div>`;

    // GitHub Hits
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="github-content">GitHub Hits (${data.github_hits?.length || 0})</button>
      <div class="accordion-content" id="github-content">
        <ul>${data.github_hits?.map(h => `<li><a href="${escapeHtml(h.url)}" target="_blank">${escapeHtml(h.repository || "")}/${escapeHtml(h.path || "")}</a></li>`).join("") || "<li>No GitHub hits found.</li>"}</ul>
      </div>
    </div>`;

    // Pastebin Hits
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="pastebin-content">Pastebin Hits (${data.paste_hits?.length || 0})</button>
      <div class="accordion-content" id="pastebin-content">
        <ul>${data.paste_hits?.map(h => `<li><a href="${escapeHtml(h.url)}" target="_blank">${escapeHtml(h.snippet?.slice(0, 100) + (h.snippet?.length > 100 ? "..." : "") || "Pastebin link")}</a></li>`).join("") || "<li>No Pastebin hits found.</li>"}</ul>
      </div>
    </div>`;

    // S3 Buckets
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="s3-content">S3 Buckets (${data.s3_buckets?.length || 0})</button>
      <div class="accordion-content" id="s3-content">
        <ul>${data.s3_buckets?.map(b => `<li>${escapeHtml(b.bucket)} (<a href="${escapeHtml(b.url)}" target="_blank">${b.status}</a>)</li>`).join("") || "<li>No S3 buckets found.</li>"}</ul>
      </div>
    </div>`;

    // CVEs with Chart
    const allCves = [];
    Object.entries(data.cves || {}).forEach(([software, cves]) => {
      cves.forEach(cve => {
        allCves.push({ software, ...cve });
      });
    });
    const cveCount = allCves.length;
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="cves-content">CVEs (${cveCount})</button>
      <div class="accordion-content" id="cves-content">
        <canvas id="cveChart" style="max-height: 300px; margin-bottom: 20px;"></canvas>
        <div class="cve-filter">
          <label for="cveSeverityFilter">Filter by CVSS:</label>
          <select id="cveSeverityFilter">
            <option value="all">All</option>
            <option value="high">High (7.0-10.0)</option>
            <option value="medium">Medium (4.0-6.9)</option>
            <option value="low">Low (0.0-3.9)</option>
          </select>
        </div>
        ${Object.entries(data.cves || {}).map(([software, cves]) => `
          <h4>${escapeHtml(software)}</h4>
          <ul class="cve-list">${cves.map(cve => {
            const cvss = parseFloat(cve.cvss);
            const severityClass = !isNaN(cvss)
              ? cvss >= 7.0 ? 'cve-high' : cvss >= 4.0 ? 'cve-medium' : 'cve-low'
              : '';
            return `<li class="${severityClass}" data-cvss="${cvss || 0}">
              ${escapeHtml(cve.id)} (CVSS: ${cvss || 'N/A'}, Source: ${escapeHtml(cve.source || 'Unknown')}${cve.ip ? `, IP: ${escapeHtml(cve.ip)}` : ''}): 
              ${escapeHtml(cve.summary?.slice(0, 100) + (cve.summary?.length > 100 ? "..." : "") || "No summary")} 
              (<a href="${escapeHtml(cve.references?.[0] || "#")}" target="_blank">Details</a>)
            </li>`;
          }).join("")}</ul>
        `).join("") || "<p>No CVEs found.</p>"}
      </div>
    </div>`;

    // Shodan
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="shodan-content">Shodan Results (${Object.keys(data.shodan || {}).length})</button>
      <div class="accordion-content" id="shodan-content">
        ${Object.entries(data.shodan || {}).map(([ip, info]) => `
          <h4>${escapeHtml(ip)}</h4>
          <pre>${escapeHtml(JSON.stringify(info, null, 2))}</pre>
        `).join("") || "<p>No Shodan results.</p>"}
      </div>
    </div>`;

    // Phishing Vectors
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="phishing-content">Phishing Vectors</button>
      <div class="accordion-content" id="phishing-content">
        <h4>MX Servers</h4>
        <ul>${data.phishing_vectors?.mx_servers?.map(s => `<li>${escapeHtml(s)}</li>`).join("") || "<li>No MX servers found.</li>"}</ul>
        <h4>Typosquat Domains</h4>
        <ul>${data.phishing_vectors?.typosquat_domains?.map(d => `<li>${escapeHtml(d)}</li>`).join("") || "<li>No typosquat domains found.</li>"}</ul>
      </div>
    </div>`;

    // SpiderFoot
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="spiderfoot-content">SpiderFoot Events</button>
      <div class="accordion-content" id="spiderfoot-content">
        <pre>${escapeHtml(JSON.stringify(data.spiderfoot_events || [], null, 2))}</pre>
      </div>
    </div>`;

    // Output Files
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="output-files-content">Output Files</button>
      <div class="accordion-content" id="output-files-content">
        <ul>
          <li>JSON: ${escapeHtml(data.output_files?.json || "N/A")}</li>
          <li>Summary CSV: ${escapeHtml(data.output_files?.csv || "N/A")}</li>
          <li>CVE CSV: ${escapeHtml(data.output_files?.cve_csv || "N/A")}</li>
        </ul>
      </div>
    </div>`;

    // SSL Info
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="ssl-content">SSL Info</button>
      <div class="accordion-content" id="ssl-content">
        <pre>${escapeHtml(JSON.stringify(data.ssl_info || {}, null, 2))}</pre>
      </div>
    </div>`;

    // Amass Subdomains
    html += `<div class="accordion">
      <button class="accordion-button" aria-expanded="false" aria-controls="amass-content">Amass Subdomains (${data.amass_subdomains?.length || 0})</button>
      <div class="accordion-content" id="amass-content">
        <ul>${data.amass_subdomains?.map(s => `<li>${escapeHtml(s)}</li>`).join("") || "<li>No Amass subdomains found.</li>"}</ul>
      </div>
    </div>`;

    // Initialize accordions and CVE chart
    setTimeout(() => {
      // Accordion functionality
      document.querySelectorAll(".accordion-button").forEach(button => {
        button.addEventListener("click", () => {
          const content = button.nextElementSibling;
          const isActive = content.classList.contains("active");
          document.querySelectorAll(".accordion-content").forEach(c => {
            c.classList.remove("active");
            c.setAttribute("aria-hidden", "true");
          });
          document.querySelectorAll(".accordion-button").forEach(b => {
            b.classList.remove("active");
            b.setAttribute("aria-expanded", "false");
          });
          if (!isActive) {
            content.classList.add("active");
            content.setAttribute("aria-hidden", "false");
            button.classList.add("active");
            button.setAttribute("aria-expanded", "true");
          }
        });
      });

      // CVE filter
      const cveFilter = document.getElementById("cveSeverityFilter");
      if (cveFilter) {
        cveFilter.addEventListener("change", () => {
          const value = cveFilter.value;
          document.querySelectorAll(".cve-list li").forEach(li => {
            const cvss = parseFloat(li.dataset.cvss);
            li.style.display = "none";
            if (value === "all") {
              li.style.display = "list-item";
            } else if (value === "high" && cvss >= 7.0) {
              li.style.display = "list-item";
            } else if (value === "medium" && cvss >= 4.0 && cvss < 7.0) {
              li.style.display = "list-item";
            } else if (value === "low" && cvss < 4.0) {
              li.style.display = "list-item";
            }
          });
        });
      }

      // CVE Chart
      const cveChartCanvas = document.getElementById("cveChart");
      if (cveChartCanvas && typeof Chart !== "undefined") {
        const cveCounts = {
          high: allCves.filter(cve => parseFloat(cve.cvss) >= 7.0).length,
          medium: allCves.filter(cve => parseFloat(cve.cvss) >= 4.0 && parseFloat(cve.cvss) < 7.0).length,
          low: allCves.filter(cve => parseFloat(cve.cvss) < 4.0).length,
          unknown: allCves.filter(cve => !cve.cvss || isNaN(parseFloat(cve.cvss))).length
        };

        ```chartjs
        {
          "type": "bar",
          "data": {
            "labels": ["High (7.0-10.0)", "Medium (4.0-6.9)", "Low (0.0-3.9)", "Unknown"],
            "datasets": [{
              "label": "CVE Severity Distribution",
              "data": [${cveCounts.high}, ${cveCounts.medium}, ${cveCounts.low}, ${cveCounts.unknown}],
              "backgroundColor": ["#ff4d4d", "#ffd700", "#90ee90", "#808080"],
              "borderColor": ["#cc0000", "#cca300", "#00cc00", "#666666"],
              "borderWidth": 1
            }]
          },
          "options": {
            "scales": {
              "y": {
                "beginAtZero": true,
                "title": { "display": true, "text": "Number of CVEs" },
                "ticks": { "stepSize": 1 }
              },
              "x": {
                "title": { "display": true, "text": "Severity" }
              }
            },
            "plugins": {
              "legend": { "display": false },
              "title": { "display": true, "text": "CVE Severity Distribution" }
            }
          }
        }
        ```
      }
    }, 0);

    return html;
  }

  // Escape HTML
  function escapeHtml(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"'`=\/]/g, c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
      "/": "&#x2F;",
      "`": "&#x60;",
      "=": "&#x3D;"
    })[c]);
  }

  // Initialize UI
  initMatrixEffect();
  initFormEnhancements();
});