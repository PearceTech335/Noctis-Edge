#!/usr/bin/env python3
"""
Deliberately misconfigured test HTTP server for Noctis scanner testing.
Simulates a poorly-configured Apache/2.4.49 + PHP/7.2 stack with common
misconfigurations that security scanners should detect.

DO NOT expose this on a network you do not control.
FOR LOCAL SCANNER TESTING ONLY.
"""

import http.server
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8080

# Fake banners — simulate old Apache 2.4.49 (CVE-2021-41773 path traversal / RCE)
# and PHP 7.2.0 (multiple known CVEs including type juggling, unserialise issues)
_SERVER_HEADER  = "Apache/2.4.49 (Unix)"
_POWERED_HEADER = "PHP/7.2.0"
_GENERATOR      = "WordPress 5.8.1"


class VulnHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"  [{self.address_string()}] {self.command} {self.path} -> {fmt % args}")

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def _send(self, code: int, content_type: str, body: bytes, extra_headers: dict = None):
        self.send_response(code)
        # Deliberately verbose headers — expose version info
        self.send_header("Server", _SERVER_HEADER)
        self.send_header("X-Powered-By", _POWERED_HEADER)
        self.send_header("X-Generator", _GENERATOR)
        # Deliberately absent security headers (no X-Frame-Options, no CSP, no HSTS)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(body))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # HTTP methods
    # ------------------------------------------------------------------

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        routes = {
            "/":                self._index,
            "/admin":           self._admin,
            "/admin/index.php": self._admin,
            "/config.php":      self._config_php,
            "/config.php.bak":  self._config_php,
            "/.env":            self._dotenv,
            "/phpinfo.php":     self._phpinfo,
            "/robots.txt":      self._robots,
            "/.git/config":     self._git_config,
            "/server-status":   self._server_status,
            "/server-info":     self._server_info,
            "/api/v1/users":    self._users_api,
            "/wp-login.php":    self._wp_login,
            "/phpmyadmin":      self._phpmyadmin,
            "/backup":          self._backup_listing,
            "/backup/db.sql":   self._backup_sql,
            "/web.config":      self._web_config,
            "/.svn/entries":    self._svn_entries,
        }
        handler = routes.get(path)
        if handler:
            handler()
        elif path.startswith("/wp-admin"):
            self._wp_login()
        else:
            self._not_found(path)

    def do_POST(self):
        # Accept POST but treat identically — unauthenticated access to admin
        self.do_GET()

    def do_OPTIONS(self):
        # Exposes TRACE and CONNECT — XST risk
        self._send(200, "text/plain", b"",
                   {"Allow": "GET, POST, PUT, DELETE, OPTIONS, TRACE, CONNECT"})

    def do_TRACE(self):
        # Cross-Site Tracing (XST) — echoes request back including headers
        body = f"TRACE {self.path} HTTP/1.1\r\n".encode()
        for k, v in self.headers.items():
            body += f"{k}: {v}\r\n".encode()
        self._send(200, "message/http", body)

    # ------------------------------------------------------------------
    # Page handlers
    # ------------------------------------------------------------------

    def _index(self):
        body = b"""<!DOCTYPE html>
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1>
<table>
  <tr><th>Name</th><th>Last Modified</th><th>Size</th></tr>
  <tr><td><a href="/admin/">admin/</a></td><td>2024-01-15</td><td>-</td></tr>
  <tr><td><a href="/backup/">backup/</a></td><td>2024-01-10</td><td>-</td></tr>
  <tr><td><a href="/config.php">config.php</a></td><td>2024-01-05</td><td>1.2K</td></tr>
  <tr><td><a href="/phpinfo.php">phpinfo.php</a></td><td>2023-12-01</td><td>48K</td></tr>
  <tr><td><a href="/.git/config">.git/config</a></td><td>2024-01-15</td><td>0.3K</td></tr>
</table>
<address>Apache/2.4.49 (Unix) Server at localhost Port 8080</address>
</body>
</html>"""
        self._send(200, "text/html", body)

    def _admin(self):
        body = b"""<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h1>Admin Panel</h1>
<p>Welcome, <strong>admin</strong>. You are logged in.</p>
<p>Database connection: mysql://admin:Password123!@127.0.0.1:3306/appdb</p>
<p>API Key: sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6</p>
<p>Environment: production</p>
</body>
</html>"""
        self._send(200, "text/html", body)

    def _config_php(self):
        body = b"""<?php
// Database configuration - do not commit to version control
define('DB_HOST',   'localhost');
define('DB_USER',   'root');
define('DB_PASS',   'Password123!');
define('DB_NAME',   'appdb');
define('APP_SECRET', 'c3VwZXJzZWNyZXRrZXkxMjM0NQ==');
define('SMTP_PASS', 'mailpassword');
?>"""
        self._send(200, "text/plain", body)

    def _dotenv(self):
        body = b"""APP_ENV=production
APP_KEY=base64:c3VwZXJzZWNyZXRrZXkxMjM0NTY3ODkwMTIzNDU2
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=appdb
DB_USERNAME=root
DB_PASSWORD=Password123!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
MAIL_PASSWORD=smtp-password-here
"""
        self._send(200, "text/plain", body)

    def _phpinfo(self):
        body = b"""<!DOCTYPE html>
<html>
<head><title>phpinfo()</title></head>
<body>
<h1>PHP Version 7.2.0</h1>
<table>
  <tr><td>PHP Version</td><td>7.2.0</td></tr>
  <tr><td>System</td><td>Linux webserver 4.15.0-20-generic x86_64</td></tr>
  <tr><td>allow_url_fopen</td><td>On</td></tr>
  <tr><td>allow_url_include</td><td>On</td></tr>
  <tr><td>expose_php</td><td>On</td></tr>
  <tr><td>display_errors</td><td>On</td></tr>
  <tr><td>register_globals</td><td>On</td></tr>
  <tr><td>open_basedir</td><td>no value</td></tr>
  <tr><td>disable_functions</td><td>no value</td></tr>
  <tr><td>upload_max_filesize</td><td>256M</td></tr>
</table>
</body>
</html>"""
        self._send(200, "text/html", body)

    def _robots(self):
        body = b"""User-agent: *
Disallow: /admin
Disallow: /admin/
Disallow: /backup
Disallow: /config.php
Disallow: /phpmyadmin
Disallow: /phpmyadmin/
Disallow: /.git
Disallow: /.env
Disallow: /api/v1/users
"""
        self._send(200, "text/plain", body)

    def _git_config(self):
        body = b"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/acme-corp/internal-app.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
"""
        self._send(200, "text/plain", body)

    def _server_status(self):
        body = b"""<html>
<head><title>Apache Status</title></head>
<body>
<h1>Apache Server Status for localhost</h1>
<dl>
  <dt>Server Version: Apache/2.4.49 (Unix) OpenSSL/1.1.1k</dt>
  <dt>Server MPM: prefork</dt>
  <dt>Server Built: Oct 7 2021 14:05:29</dt>
  <dt>Current Time: Monday, 12-May-2026 12:00:00 UTC</dt>
  <dt>Total accesses: 14502</dt>
</dl>
</body></html>"""
        self._send(200, "text/html", body)

    def _server_info(self):
        body = b"""<html>
<head><title>Apache Server Information</title></head>
<body>
<h1>Apache Server Information</h1>
<pre>
Server version: Apache/2.4.49 (Unix)
Server built:   Oct  7 2021 14:05:29
Module: mod_status
Module: mod_info
Module: mod_rewrite (enabled)
Module: mod_php7 (7.2.0)
</pre>
</body></html>"""
        self._send(200, "text/html", body)

    def _users_api(self):
        # Unauthenticated API endpoint exposing user data
        data = json.dumps([
            {"id": 1, "username": "admin",  "email": "admin@example.com",  "role": "admin",  "password_hash": "$2y$10$abcdefghijklmnopqrstuuABC123"},
            {"id": 2, "username": "jsmith", "email": "jsmith@example.com", "role": "user",   "password_hash": "$2y$10$xyz123abcdefghijklmnopqrstu"},
            {"id": 3, "username": "guest",  "email": "guest@example.com",  "role": "guest",  "password_hash": "$2y$10$000000000000000000000000000"},
        ]).encode()
        self._send(200, "application/json", data)

    def _wp_login(self):
        body = b"""<!DOCTYPE html>
<html>
<head><title>Log In &lsaquo; Test Site &#8212; WordPress</title></head>
<body id="login">
<h1>Test Site</h1>
<h2>Powered by WordPress 5.8.1</h2>
<form name="loginform" action="/wp-login.php" method="post">
  <input type="text" name="log" placeholder="Username" />
  <input type="password" name="pwd" placeholder="Password" />
  <input type="submit" value="Log In" />
</form>
</body>
</html>"""
        self._send(200, "text/html", body)

    def _phpmyadmin(self):
        body = b"""<!DOCTYPE html>
<html>
<head><title>phpMyAdmin 4.9.7</title></head>
<body>
<h1>phpMyAdmin</h1>
<p>Version 4.9.7 - Welcome to phpMyAdmin</p>
<form method="post">
  <input type="text" name="pma_username" placeholder="Username" />
  <input type="password" name="pma_password" placeholder="Password" />
  <input type="submit" value="Go" />
</form>
</body>
</html>"""
        self._send(200, "text/html", body)

    def _backup_listing(self):
        body = b"""<!DOCTYPE html>
<html>
<head><title>Index of /backup</title></head>
<body>
<h1>Index of /backup</h1>
<table>
  <tr><td><a href="/backup/db.sql">db.sql</a></td><td>2024-01-10</td><td>2.4M</td></tr>
  <tr><td><a href="/backup/db.sql.gz">db.sql.gz</a></td><td>2024-01-10</td><td>512K</td></tr>
  <tr><td><a href="/backup/app_backup_20240110.tar.gz">app_backup_20240110.tar.gz</a></td><td>2024-01-10</td><td>18M</td></tr>
</table>
<address>Apache/2.4.49 (Unix) Server at localhost Port 8080</address>
</body>
</html>"""
        self._send(200, "text/html", body)

    def _backup_sql(self):
        body = b"""-- MySQL dump 10.13  Distrib 8.0.27
-- Host: localhost    Database: appdb
-- Server version: 8.0.27

CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
);

INSERT INTO `users` VALUES (1,'admin','Password123!','admin@example.com');
INSERT INTO `users` VALUES (2,'jsmith','Welcome1','jsmith@example.com');
"""
        self._send(200, "text/plain", body)

    def _web_config(self):
        body = b"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection"
         connectionString="Server=localhost;Database=appdb;User Id=sa;Password=Password123!;" />
  </connectionStrings>
  <appSettings>
    <add key="ApiKey" value="sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" />
  </appSettings>
</configuration>"""
        self._send(200, "text/xml", body)

    def _svn_entries(self):
        body = b"""10

dir
1
https://svn.example.com/repos/app
https://svn.example.com/repos
"""
        self._send(200, "text/plain", body)

    def _not_found(self, path: str):
        body = (
            f"<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
            f"<body><h1>Not Found</h1>"
            f"<p>The requested URL {path} was not found on this server.</p>"
            f"<hr><address>Apache/2.4.49 (Unix) Server at localhost Port {PORT}</address>"
            f"</body></html>"
        ).encode()
        self._send(404, "text/html", body)


if __name__ == "__main__":
    print("=" * 60)
    print("  Noctis Test Server — DELIBERATELY MISCONFIGURED")
    print("  DO NOT expose outside localhost / test network")
    print("=" * 60)
    print(f"  Listening on http://0.0.0.0:{PORT}")
    print(f"  Simulates: Apache/2.4.49 + PHP/7.2.0 + WordPress 5.8.1")
    print(f"  Notable misconfigs:")
    print(f"    GET /              → directory listing")
    print(f"    GET /admin         → unauthenticated admin panel")
    print(f"    GET /config.php    → plaintext DB credentials")
    print(f"    GET /.env          → .env with secrets/API keys")
    print(f"    GET /phpinfo.php   → full phpinfo() output")
    print(f"    GET /.git/config   → exposed git config")
    print(f"    GET /server-status → Apache mod_status")
    print(f"    GET /api/v1/users  → unauthenticated user dump")
    print(f"    GET /backup/db.sql → database backup with credentials")
    print(f"    TRACE /            → XST (Cross-Site Tracing)")
    print(f"    OPTIONS /          → exposes dangerous HTTP methods")
    print("  Press Ctrl+C to stop")
    print("=" * 60)
    server = HTTPServer(("0.0.0.0", PORT), VulnHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
