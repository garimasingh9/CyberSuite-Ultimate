// ===============================
// Smooth scroll for "Get Started"
// ===============================
document.getElementById("get-started-btn").addEventListener("click", () => {
  document.getElementById("chatbot").scrollIntoView({ behavior: "smooth" });
});

// ===============================
// Theme: Dark / Light toggle
// ===============================
const themeToggleBtn = document.getElementById("theme-toggle");
const THEME_KEY = "cybersuite-theme";

function applyTheme(theme) {
  if (theme === "light") {
    document.body.classList.add("light");
    themeToggleBtn.textContent = "🌙 Dark";
  } else {
    document.body.classList.remove("light");
    themeToggleBtn.textContent = "☀ Light";
  }
}

const savedTheme = localStorage.getItem(THEME_KEY) || "dark";
applyTheme(savedTheme);

themeToggleBtn.addEventListener("click", () => {
  const newTheme = document.body.classList.contains("light") ? "dark" : "light";
  localStorage.setItem(THEME_KEY, newTheme);
  applyTheme(newTheme);
});

// ===============================
// Mock Vulnerability Scanner
// ===============================
const scanForm = document.getElementById("scan-form");
const scanUrlInput = document.getElementById("scan-url");
const scanStatus = document.getElementById("scan-status");
const scanResults = document.getElementById("scan-results");

function delay(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = scanUrlInput.value.trim();
  if (!url) return;

  scanStatus.classList.remove("hidden");
  scanResults.classList.add("hidden");
  scanStatus.textContent = `Simulating Nmap-style scan for ${url}...`;

  await delay(1200);

  scanStatus.textContent = `Simulation complete for ${url}. Example findings below.`;

  const findings = [
    {
      title: "Open Ports Detected",
      severity: "Info",
      detail: "80/tcp (HTTP), 443/tcp (HTTPS), 22/tcp (SSH). Simulated output.",
    },
    {
      title: "Possible XSS Risk",
      severity: "Medium",
      detail:
        "Search page reflects user input. Output encoding and CSP recommended.",
    },
    {
      title: "Missing Security Headers",
      severity: "Low",
      detail:
        "X-Frame-Options, Content-Security-Policy not detected in sample response.",
    },
  ];

  scanResults.innerHTML = `
    <h3>Simulated Findings (Educational Only)</h3>
    <ul>
      ${findings
        .map(
          (f) => `
        <li>
          <span>[${f.severity}]</span> ${f.title}<br />
          <small>${f.detail}</small>
        </li>
      `
        )
        .join("")}
    </ul>
    <p style="font-size:0.8rem; margin-top:0.5rem; opacity:0.8;">
      This is a front-end demo. Real scanning (Nmap, etc.) must only be done on
      systems you own or have written permission to test.
    </p>
  `;

  scanResults.classList.remove("hidden");
});

// ===============================
// Chatbot with cyber knowledge
// ===============================
const chatMessages = document.getElementById("chat-messages");
const chatInput = document.getElementById("chat-input");
const typingIndicator = document.getElementById("typing-indicator");
const modeSelect = document.getElementById("mode-select");
const clearChatBtn = document.getElementById("clear-chat-btn");
const voiceToggleBtn = document.getElementById("voice-toggle");
const downloadPdfBtn = document.getElementById("download-pdf-btn");

let voiceEnabled = false;

// ---- Voice toggle ----
voiceToggleBtn.addEventListener("click", () => {
  voiceEnabled = !voiceEnabled;
  voiceToggleBtn.textContent = voiceEnabled ? "🔊 Voice On" : "🔇 Voice Off";
});

// ---- Add message to DOM ----
function addMessage(text, sender, options = {}) {
  const row = document.createElement("div");
  row.classList.add("message-row", sender);

  const bubble = document.createElement("div");
  bubble.classList.add("message-bubble");

  row.appendChild(bubble);
  chatMessages.appendChild(row);
  chatMessages.scrollTop = chatMessages.scrollHeight;

  if (sender === "bot" && options.typingAnimation) {
    typeTextWithAnimation(bubble, text);
  } else {
    bubble.textContent = text;
  }

  // Voice output for bot
  if (sender === "bot" && voiceEnabled && "speechSynthesis" in window) {
    const utter = new SpeechSynthesisUtterance(text);
    utter.rate = 1.0;
    window.speechSynthesis.speak(utter);
  }
}

// ---- AI-style typing animation ----
async function typeTextWithAnimation(element, text) {
  element.textContent = "";
  for (let i = 0; i < text.length; i++) {
    element.textContent += text[i];
    await delay(15); // typing speed
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
}

// ---- Cybersecurity knowledge base ----
function getCyberResponse(msg, mode) {
  msg = msg.toLowerCase().trim();

  // greetings & help
  if (/(hi|hello|hey)\b/.test(msg)) {
    return "Hello! I'm your CyberSuite Cybersecurity Assistant. Ask me anything about XSS, SQL injection, Nmap, Wireshark, malware, OSINT, DFIR, or cloud security. Type 'help' for ideas.";
  }

  if (msg.includes("help") || msg.includes("commands")) {
    return `
You can ask things like:
• what is cybersecurity / cia triad / encryption
• xss, sql injection, csrf, ssrf, clickjacking
• ddos, bruteforce, mitm, phishing
• tools: nmap, wireshark, burp suite, metasploit
• malware types: virus, worm, trojan, ransomware, rat
• osint, shodan, google dorking
• forensics, hash, log analysis, memory analysis
Commands (advanced/pro):
• /scan example.com (simulated)
• /explain xss
    `;
  }

  // BASIC CYBER
  if (msg.includes("what is cybersecurity"))
    return "Cybersecurity protects systems, networks, and data from attacks and unauthorized access, using tools like firewalls, encryption, monitoring, and secure design.";

  if (msg.includes("cia triad"))
    return "CIA Triad: Confidentiality (keep data secret), Integrity (keep data correct), Availability (keep systems online).";

  if (msg.includes("encryption"))
    return "Encryption converts readable data to unreadable form using a key. Symmetric: AES; Asymmetric: RSA, ECC.";

  if (msg.includes("hashing"))
    return "Hashing maps data to a fixed value (hash). Good for integrity checks and password storage with salt. SHA-256 is strong; MD5 and SHA-1 are weak.";

  // WEB SECURITY
  if (msg.includes("xss"))
    return "XSS (Cross-Site Scripting) lets attackers inject JavaScript into pages viewed by other users. Defenses: input validation, output encoding, Content-Security-Policy.";

  if (msg.includes("sql injection"))
    return "SQL Injection modifies database queries via user input. Prevent using parameterized queries, ORM, least-privilege DB accounts, and input validation.";

  if (msg.includes("csrf"))
    return "CSRF (Cross-Site Request Forgery) tricks a user into making unwanted requests while logged in. Use CSRF tokens, SameSite cookies, and re-authentication.";

  if (msg.includes("ssrf"))
    return "SSRF (Server-Side Request Forgery) forces a server to make requests to internal services. Use allowlists, input validation, and network segmentation.";

  if (msg.includes("clickjacking"))
    return "Clickjacking overlays invisible frames over a page so users click on hidden elements. Mitigation: X-Frame-Options DENY / SAMEORIGIN or frame-ancestors in CSP.";

  if (msg.includes("security headers"))
    return "Important security headers: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy.";

  if (msg.includes("owasp"))
    return `OWASP Top 10 (web risks):
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Identification & Authentication Failures
8. Software & Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)`;

  // NETWORK / ATTACKS
  if (msg.includes("ddos"))
    return "DDoS (Distributed Denial of Service) overloads a target with huge traffic from many sources. Defenses: WAF, rate limiting, CDNs, scrubbing services, capacity planning.";

  if (msg.includes("bruteforce"))
    return "Bruteforce tries many passwords or keys until it finds the correct one. Defend with account lockout, strong hashing, MFA, and CAPTCHAs.";

  if (msg.includes("mitm") || msg.includes("man in the middle"))
    return "MITM intercepts communication between two parties. Protection: HTTPS everywhere, VPN, certificate pinning, avoiding open Wi-Fi.";

  if (msg.includes("phishing"))
    return "Phishing uses fake emails or sites to steal credentials or money. Defenses: awareness training, email filters, domain checks, MFA.";

  // MALWARE
  if (msg.includes("virus"))
    return "Virus attaches to files and spreads when infected files run.";

  if (msg.includes("worm"))
    return "Worm self-replicates across networks without user action.";

  if (msg.includes("trojan"))
    return "Trojan appears legitimate but does malicious actions once installed.";

  if (msg.includes("ransomware"))
    return "Ransomware encrypts data and demands payment. Defenses: backups, patching, limited privileges, email filtering, EDR.";

  if (msg.includes("rat"))
    return "RAT (Remote Access Trojan) gives attackers remote control of a victim machine.";

  // TOOLS
  if (msg.includes("nmap"))
    return "Nmap is a network scanner. Common commands:\n- nmap -sV target\n- nmap -A target\n- nmap -p- target\nUse only on systems you own or have written permission to test.";

  if (msg.includes("wireshark"))
    return "Wireshark captures and analyzes network packets. Useful display filters: http, dns, tcp.port==80, ip.addr==x.x.x.x.";

  if (msg.includes("burp"))
    return "Burp Suite is a web pentesting toolset: Proxy, Repeater, Intruder, Scanner. Great for testing XSS, SQLi, auth logic, etc.";

  if (msg.includes("metasploit"))
    return "Metasploit is an exploitation framework. Typical flow: search module, use exploit, set options (RHOSTS, LHOST), set payload, run.";

  // OSINT
  if (msg.includes("osint"))
    return "OSINT (Open Source Intelligence) collects info from public sources. Tools: Shodan, Censys, Spyse, Maltego, SpiderFoot, Google dorking.";

  if (msg.includes("google dork"))
    return "Google dorking uses advanced operators like site:, filetype:, intitle:, inurl: to find sensitive info accidentally exposed.";

  if (msg.includes("shodan"))
    return "Shodan is a search engine for internet-connected devices, showing open ports, services, banners, and sometimes vulnerabilities.";

  // DFIR / FORENSICS
  if (msg.includes("forensics"))
    return "Digital forensics and incident response (DFIR) investigates attacks: acquire evidence, analyze logs, timelines, memory, and artifacts to understand what happened.";

  if (msg.includes("log analysis"))
    return "Log analysis reviews system, application, and security logs for suspicious events like failed logins, privilege changes, or anomalous requests.";

  if (msg.includes("memory analysis"))
    return "Memory analysis uses tools like Volatility to inspect RAM images for malware, processes, network connections, and credentials.";

  if (msg.includes("hash"))
    return "Hashes verify integrity. Combine hashes with salts and slow algorithms (bcrypt, Argon2) for password storage.";

  // LINUX / CLOUD
  if (msg.includes("chmod"))
    return "chmod changes Linux file permissions. Example: chmod 755 script.sh (rwxr-xr-x).";

  if (msg.includes("chown"))
    return "chown changes file owner and group. Example: chown user:group file.txt.";

  if (msg.includes("ufw"))
    return "UFW is a simple firewall on Linux. Common commands: ufw allow 22, ufw deny 80, ufw enable.";

  if (msg.includes("aws security"))
    return "AWS security relies on IAM (users/roles/policies), Security Groups, NACLs, VPC, KMS, CloudTrail, GuardDuty. Most issues are misconfigurations.";

  // ADVANCED / PRO COMMANDS
  if (mode === "advanced" || mode === "pro") {
    if (msg.startsWith("/scan")) {
      const parts = msg.split(" ");
      const target = parts[1] || "target.com";
      return `Starting simulated scan for ${target}...

[01] Discovering open ports (like nmap -sV)...
[02] Checking HTTP response & headers...
[03] Looking for common web issues (XSS, SQLi patterns)...
[04] Checking for missing security headers (CSP, HSTS)...

Result: This is a simulation. For real scans, run Nmap on authorized targets only.`;
    }

    if (msg.startsWith("/explain")) {
      const topic = msg.replace("/explain", "").trim() || "that topic";
      return `Deep explanation for "${topic}" would include: definition, attack flow, real examples, detection methods, and mitigation steps. For your report, structure it as: intro, how it works, impact, prevention, and references (OWASP / official docs).`;
    }
  }

  // PRO MODE generic answer
  if (mode === "pro") {
    return `Your question "${msg}" touches cybersecurity concepts.

Think in layers:
• Identify asset & threat model
• Consider attacks (network, web, social, physical)
• Choose controls (technical, admin, physical)
• Monitor & respond (logging, alerts, incident response)

Ask me specific: "owasp top 10", "nmap usage", "how to secure login system", or "types of malware".`;
  }

  // default fallback
  return "I might not have a direct rule for that. Try asking about XSS, SQL injection, OWASP, Nmap, Wireshark, malware types, OSINT, DFIR, cloud security, or type 'help'.";
}

// ---- Handle user message ----
async function handleUserMessage(text) {
  const mode = modeSelect.value;
  addMessage(text, "user");

  typingIndicator.classList.remove("hidden");
  await delay(400);
  typingIndicator.classList.add("hidden");

  const reply = getCyberResponse(text, mode);
  addMessage(reply, "bot", { typingAnimation: true });
}

// ---- Chat form submit ----
document.getElementById("chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const text = chatInput.value.trim();
  if (!text) return;
  chatInput.value = "";
  handleUserMessage(text);
});

// Clear chat
clearChatBtn.addEventListener("click", () => {
  chatMessages.innerHTML = "";
});

// Initial welcome message
addMessage(
  "Hi, I'm the CyberSuite chatbot. Ask any cybersecurity question or type 'help' to see what I know.",
  "bot",
  { typingAnimation: true }
);

// ===============================
// Download chat as PDF
// ===============================
downloadPdfBtn.addEventListener("click", () => {
  if (!window.jspdf) {
    alert("jsPDF library not loaded.");
    return;
  }
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  let y = 10;

  const rows = chatMessages.querySelectorAll(".message-row");

  rows.forEach((row) => {
    const sender = row.classList.contains("user") ? "You" : "Bot";
    const text = row.textContent.trim();
    const line = `${sender}: ${text}`;

    const lines = doc.splitTextToSize(line, 180);
    if (y + lines.length * 7 > 280) {
      doc.addPage();
      y = 10;
    }
    doc.text(lines, 10, y);
    y += lines.length * 7;
  });

  doc.save("cybersuite-chat.pdf");
});

// ===============================
// Cyber Quiz Module
// ===============================
const quizQuestions = [
  {
    q: "What does the 'C' in CIA Triad stand for?",
    options: ["Control", "Confidentiality", "Communication", "Cryptography"],
    correct: 1,
    explanation: "CIA Triad = Confidentiality, Integrity, Availability.",
  },
  {
    q: "Which tool is mainly used for network port scanning?",
    options: ["Wireshark", "Nmap", "Burp Suite", "Metasploit"],
    correct: 1,
    explanation: "Nmap is a popular network scanner for ports and services.",
  },
  {
    q: "XSS is primarily a vulnerability in which layer?",
    options: ["Network", "Web application", "Physical", "Cloud"],
    correct: 1,
    explanation: "XSS is a web application vulnerability.",
  },
  {
    q: "Ransomware usually does what?",
    options: [
      "Deletes all logs",
      "Steals credentials only",
      "Encrypts files and demands money",
      "Installs antivirus",
    ],
    correct: 2,
    explanation:
      "Ransomware encrypts data and demands payment to restore access.",
  },
  {
    q: "Which header helps prevent clickjacking?",
    options: [
      "X-Frame-Options",
      "Content-Type",
      "Referrer-Policy",
      "Accept-Encoding",
    ],
    correct: 0,
    explanation:
      "X-Frame-Options (or CSP frame-ancestors) protects against clickjacking.",
  },
];

let currentQuizIndex = 0;
let quizScore = 0;

const quizQuestionEl = document.getElementById("quiz-question");
const quizOptionsEl = document.getElementById("quiz-options");
const quizFeedbackEl = document.getElementById("quiz-feedback");
const quizScoreEl = document.getElementById("quiz-score");
const nextQuestionBtn = document.getElementById("next-question-btn");
const restartQuizBtn = document.getElementById("restart-quiz-btn");

function renderQuizQuestion() {
  const q = quizQuestions[currentQuizIndex];
  quizQuestionEl.textContent = `Q${currentQuizIndex + 1}. ${q.q}`;
  quizOptionsEl.innerHTML = "";
  quizFeedbackEl.textContent = "";

  q.options.forEach((opt, idx) => {
    const btn = document.createElement("button");
    btn.className = "quiz-option-btn";
    btn.textContent = opt;
    btn.addEventListener("click", () => handleQuizAnswer(idx));
    quizOptionsEl.appendChild(btn);
  });

  quizScoreEl.textContent = `Score: ${quizScore} / ${quizQuestions.length}`;
}

function handleQuizAnswer(selectedIndex) {
  const q = quizQuestions[currentQuizIndex];
  const isCorrect = selectedIndex === q.correct;

  if (isCorrect) {
    quizScore++;
    quizFeedbackEl.textContent = "✅ Correct! " + q.explanation;
  } else {
    quizFeedbackEl.textContent =
      "❌ Incorrect. " +
      q.explanation +
      ` (Correct: ${q.options[q.correct]})`;
  }

  // Disable buttons after answer
  const buttons = quizOptionsEl.querySelectorAll("button");
  buttons.forEach((btn) => (btn.disabled = true));

  quizScoreEl.textContent = `Score: ${quizScore} / ${quizQuestions.length}`;
}

nextQuestionBtn.addEventListener("click", () => {
  currentQuizIndex++;
  if (currentQuizIndex >= quizQuestions.length) {
    quizQuestionEl.textContent = "Quiz complete!";
    quizOptionsEl.innerHTML = "";
    quizFeedbackEl.textContent = `Your final score is ${quizScore} out of ${quizQuestions.length}.`;
  } else {
    renderQuizQuestion();
  }
});

restartQuizBtn.addEventListener("click", () => {
  quizScore = 0;
  currentQuizIndex = 0;
  renderQuizQuestion();
});

// Initial quiz render
renderQuizQuestion();
