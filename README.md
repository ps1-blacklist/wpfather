<h1 align="center">
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Shield.png" alt="Shield" width="40" height="40" />
  WPFather — WordPress Vulnerability Scanner
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-cross--platform-blue?style=flat-square" alt="Platform">
</p>

<p>WPFather is a single-binary WordPress security scanner and reconnaissance tool written in Go. It runs a fixed set of non-destructive, read-only checks against a WordPress site and prints results directly to the terminal — no config files, no flags, no output files.</p>

<p>Built for authorized penetration testing, bug bounty recon, and WordPress hardening audits.</p>

<hr>

<h2>
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Objects/Package.png" alt="Package" width="30" height="30" />
  Installation
</h2>

<pre><code>go install github.com/ps1-blacklist/wpfather@latest</code></pre>

<hr>

<h2>
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Travel%20and%20places/Star.png" alt="Star" width="30" height="30" />
  Features
</h2>

<marquee behavior="scroll" direction="left" scrollamount="3">
  🔍 16 Scan Modules &nbsp;|&nbsp; 🎯 Zero Config &nbsp;|&nbsp; ⚡ Single Binary &nbsp;|&nbsp; 🔒 Read-Only &nbsp;|&nbsp; 📋 Copy-Paste Ready Output
</marquee>

<p>WPFather runs 16 scan modules per target:</p>

<table>
  <thead>
    <tr>
      <th>Module</th>
      <th>What it checks</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>🔄 Redirect Chain</td><td>Follows redirects, flags scope/host changes</td></tr>
    <tr><td>🔒 TLS/SSL</td><td>Protocol version, certificate expiry, self-signed detection</td></tr>
    <tr><td>🛡️ WAF/CDN Fingerprint</td><td>Cloudflare, Sucuri, Akamai, CloudFront, Fastly</td></tr>
    <tr><td>🤖 robots.txt & sitemap</td><td>Parses disallowed paths for sensitive references</td></tr>
    <tr><td>📡 HTTP Methods</td><td>Detects risky methods (PUT, DELETE, TRACE, CONNECT)</td></tr>
    <tr><td>🍪 Cookie Flags</td><td>Missing Secure / HttpOnly / SameSite / Path attributes</td></tr>
    <tr><td>⚙️ WordPress Core</td><td>Version disclosure, debug mode, readme/install/cron exposure</td></tr>
    <tr><td>📨 XML-RPC</td><td>pingback SSRF vector, multicall brute-force vector, user validation</td></tr>
    <tr><td>👥 Users</td><td>REST API user enumeration, author-ID enumeration</td></tr>
    <tr><td>🔌 Plugins & Themes</td><td>Slug/version detection, NVD CVE lookup</td></tr>
    <tr><td>📁 Sensitive Files</td><td>Backups, <code>.git</code>, <code>.env</code>, config backups, logs (25+ paths)</td></tr>
    <tr><td>📂 Directory Listing</td><td>Open directory index detection</td></tr>
    <tr><td>🛡️ Security Headers</td><td>HSTS, CSP, X-Frame-Options, and more</td></tr>
    <tr><td>💧 Info Leaks</td><td>Internal IPs, emails, API keys, AWS keys, private keys</td></tr>
    <tr><td>🎯 SSRF Confirmation</td><td>Verifies pingback SSRF against internal/metadata targets</td></tr>
  </tbody>
</table>

<p>Every finding includes the exact URL that triggered it, so results can be copy-pasted straight into a browser or <code>curl</code> for manual verification.</p>

<hr>

<h2>
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Travel%20and%20places/Rocket.png" alt="Rocket" width="30" height="30" />
  Usage
</h2>

<p>No flags, no arguments. Run the binary and follow the prompts:</p>

<pre><code>wpfather</code></pre>

<pre>
📥 Your Domain: example.com
Type 'yes' to confirm you are authorized to scan example.com:
</pre>

<p>The tool confirms authorization, runs all 16 modules, and prints findings live as they're found, followed by a summary with a risk score out of 100.</p>

<hr>

<h2>
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Symbols/Warning.png" alt="Warning" width="30" height="30" />
  Responsible Use
</h2>

<p>Only run WPFather against systems you own or have explicit written authorization to test. Unauthorized scanning may violate the CFAA or equivalent laws in your jurisdiction.</p>

<hr>

<h2>
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/People/Man%20Technologist.png" alt="Technologist" width="30" height="30" />
  Author
</h2>

<p>Built by <strong>ps1-blacklist</strong> — Red Squad Bangladesh</p>

<p>🔗 GitHub: <a href="https://github.com/ps1-blacklist">github.com/ps1-blacklist</a></p>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Smilies/Red%20Heart.png" alt="Red Heart" width="40" height="40" />
  <img src="https://raw.githubusercontent.com/Tarikul-Islam-Anik/Animated-Fluent-Emojis/master/Emojis/Hand%20gestures/Thumbs%20Up.png" alt="Thumbs Up" width="40" height="40" />
</p>

<p align="center"><sub>Made with ❤️ for the security community</sub></p>
