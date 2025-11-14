# Security Policy

## Reporting Security Vulnerabilities

**DO NOT** open a public GitHub issue for security vulnerabilities. Instead, please report security issues directly to:

📧 **[maximilian.rink@telekom.de](mailto:maximilian.rink@telekom.de)**

Please include:
- A clear description of the vulnerability
- Steps to reproduce (if applicable)
- Affected component(s) and version(s)
- Potential impact and severity
- Any suggested fixes (if you have them)

We take all security reports seriously and will respond within 24 hours to acknowledge receipt. We will keep you updated on the investigation and remediation progress.

---

## Security Practices

### Our Commitment

The Kubernetes Breakglass project is committed to security by design:

- **Audit Trail** - All privilege escalation requests and approvals are audited and logged
- **Time-Bounded Access** - Sessions automatically expire after configured duration
- **Approval Workflow** - Requests require explicit approval before access is granted
- **Webhook Integration** - Real-time authorization enforcement via Kubernetes webhooks
- **Least Privilege** - Access is restricted to explicitly configured escalations only
- **OIDC Authentication** - Integration with industry-standard identity providers

### Security Scanning

This project uses multiple security tools to maintain code quality:

- **CodeQL** - Static analysis for security vulnerabilities
- **Dependabot** - Dependency vulnerability tracking
- **npm audit** - Frontend dependency security scanning
- **REUSE** - License compliance verification
- **OpenSSF Scorecard** - Open source security best practices

### Dependencies

We actively monitor and update dependencies to address security issues:

- Frontend dependencies are scanned with `npm audit`
- Go dependencies are kept up-to-date with security patches
- Container images are built on secure base images
- All dependencies are vendored or pinned to specific versions

### Data Protection

Kubernetes Breakglass handles sensitive data:

- **Session Records** - Stored as Kubernetes resources with RBAC controls
- **Audit Logs** - Available for security monitoring and compliance
- **User Information** - Collected from OIDC providers, not stored locally
- **Credentials** - Never logged or displayed in plaintext
- **TLS/HTTPS** - All communication should use encrypted connections

---

## Security Considerations for Operators

### Prerequisites

1. **Secure OIDC Provider** - Configure with trusted identity provider (Keycloak, Azure AD, etc.)
2. **Network Security** - Deploy behind firewall/network policies
3. **RBAC Configuration** - Properly configure Kubernetes RBAC on all clusters
4. **TLS Certificates** - Use valid, trusted certificates for all endpoints
5. **Secret Management** - Store Breakglass configuration in secure secret management

### Configuration Best Practices

- **Approver Groups** - Keep approver groups small and well-documented
- **Escalation Duration** - Set reasonable time limits for session duration
- **Monitoring** - Enable Prometheus metrics and monitor for anomalies
- **Logging** - Forward logs to SIEM for security monitoring
- **Webhooks** - Ensure webhook endpoints are properly secured and authenticated

### Deployment Security

- **Images** - Use container image scanning in your registry
- **RBAC** - Follow least privilege principle for Breakglass service account
- **Network Policies** - Restrict network access to authorized sources
- **Pod Security** - Use Pod Security Standards (restricted profile recommended)
- **Service Accounts** - Limit permissions to minimum required

---

## Incident Response

In case of a confirmed security vulnerability:

1. **Acknowledgment** - We will acknowledge receipt within 24 hours
2. **Assessment** - We will evaluate severity and affected versions
3. **Disclosure Coordination** - We will coordinate a timeline for public disclosure
4. **Patch Release** - A patch will be released as soon as possible
5. **Notification** - Users will be notified of available updates

### Severity Levels

- **Critical** - Affects authentication/authorization; immediate patch required
- **High** - Significant security issue; patch within 1 week
- **Medium** - Moderate security impact; patch within 2 weeks
- **Low** - Minor security concern; included in next release

---

## Security Disclosure

We follow responsible disclosure practices:

- Vulnerability reporters are credited unless they request anonymity
- We provide a reasonable time for affected users to update before public disclosure
- We coordinate with security researchers and industry partners
- We maintain a transparent communication policy

---

## Compliance

This project adheres to:

- **OpenSSF Best Practices** - Security recommendations from the Open Source Security Foundation
- **OWASP Top 10** - Mitigation of common web application vulnerabilities
- **CIS Kubernetes Benchmarks** - Kubernetes security hardening guidelines
- **REUSE Specification** - Software license compliance

---

## Security Resources

### For Users

- [Installation Guide](./docs/installation.md) - Secure deployment instructions
- [Configuration Reference](./docs/) - Security-related configuration options
- [Troubleshooting](./docs/troubleshooting.md) - Common issues and solutions

### For Contributors

- [Contributing Guidelines](./CONTRIBUTING.md) - How to contribute securely
- [Code Review Process](./CONTRIBUTING.md) - Security in code review
- [Building from Source](./docs/building.md) - Secure build practices

### External Resources

- [OWASP Privilege Escalation](https://owasp.org/www-community/attacks/Privilege_Escalation)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [OIDC Security Considerations](https://openid.net/specs/openid-connect-core-1_0.html)

---

## Version Support

Only the latest version receives security updates. We recommend:

- Staying on the latest stable release
- Monitoring GitHub releases for security patches
- Testing updates in a staging environment before production deployment
- Subscribing to GitHub notifications for critical security updates

---

## Contact

For security issues: **maximilian.rink@telekom.de**

For other inquiries: See [Contributing Guidelines](./CONTRIBUTING.md)

---

**Last Updated:** November 14, 2025

This security policy is subject to change. Check back regularly for updates.
