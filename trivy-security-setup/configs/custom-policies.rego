package trivy

# Custom OPA policy for Trivy
import data.lib.trivy

default allow = false

# Allow specific known false positives
allow {
    input.vulnerability.VulnerabilityID == "CVE-2020-12345"
    input.vulnerability.PkgName == "express"
}

# Deny critical vulnerabilities in authentication components
deny[msg] {
    input.vulnerability.Severity == "CRITICAL"
    contains(input.vulnerability.PkgName, "auth")
    msg = sprintf("Critical vulnerability in auth component: %s", [input.vulnerability.VulnerabilityID])
}
