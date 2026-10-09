# SafeVault Security Enhancement & Capstone Audit

## Overview
This repository contains the complete security audit, vulnerability remediation, role-based access control (RBAC), and automated testing suite for the **SafeVault** web application.

---

## Identified Vulnerabilities & Applied Fixes

### 1. SQL Injection (SQLi)
* **Vulnerability Identified:** The initial codebase used unsafe string concatenation to construct SQL queries, allowing attackers to manipulate queries via malicious input (e.g., `' OR '1'='1`).
* **Fix Applied:** Refactored queries to use **parameterized statements** (`SqlCommand` with explicit parameters and data types), ensuring all user inputs are treated as literal data rather than executable code.

### 2. Cross-Site Scripting (XSS)
* **Vulnerability Identified:** Unsanitized user inputs in web forms were rendered directly in the user interface, opening the application to stored/reflected XSS script injections.
* **Fix Applied:** Applied strict **output encoding** using `HttpUtility.HtmlEncode()` to escape potential HTML/script tags before rendering.

### 3. Broken Access Control (RBAC)
* **Vulnerability Identified:** Sensitive administrative endpoints were accessible without role verification.
* **Fix Applied:** Implemented Role-Based Access Control (RBAC) middleware logic to enforce `Admin` role requirements before granting access to privileged resources.

---

## Role of Microsoft Copilot in Debugging & Remediation

Microsoft Copilot assisted in:
* **Identification:** Scanning code patterns to spot unparameterized SQL queries and unescaped form output fields.
* **Remediation:** Automatically proposing parameterized C# SQL query structures and HTML sanitization routines.
* **Testing:** Generating comprehensive unit test cases targeting SQLi and XSS payloads to confirm the effectiveness of applied patches.

---

## Test Verification
The included test suite (`SecurityTests.cs`) verifies that:
* SQL injection payloads are safely parameterized and executed without query manipulation.
* XSS script tags are escaped into safe HTML entities.
* Unauthorized non-admin users are blocked from accessing restricted administrative operations.