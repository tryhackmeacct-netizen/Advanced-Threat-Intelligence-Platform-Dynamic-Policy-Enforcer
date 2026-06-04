# Security: Credential Management

This document describes how credentials are managed in the Advanced Threat Intelligence Platform.

## 🔐 Credential Storage

All sensitive credentials are managed through **environment variables** and stored in a `.env` file that is **git-ignored** for production security.

### Git Ignore Configuration

The repository includes `.gitignore` with the following entries:
```
.env           # Never commit environment file with real credentials
__pycache__/   # Python cache
*.log          # Application logs
venv/          # Virtual environment
logs/          # Runtime logs directory
```

## 📋 Elasticsearch Credentials

### Required Environment Variables

| Variable | Purpose | Required | Example |
|----------|---------|----------|---------|
| `ELASTICSEARCH_URL` | Elasticsearch server URL | Yes | `https://localhost:9200` |
| `ELASTICSEARCH_USER` | Authentication username | Yes | `elastic` |
| `ELASTICSEARCH_PASSWORD` | Authentication password | **Yes** | `SecurePassword123!` |
| `ELASTICSEARCH_CA_CERT_PATH` | CA certificate path for TLS | Yes | `/etc/elasticsearch/certs/http_ca.crt` |
| `ELASTICSEARCH_VERIFY_CERTS` | Enable TLS certificate validation | Optional | `1` (default) |

### Setup Instructions

1. **Copy the example file:**
   ```bash
   cp .env.example .env
   ```

2. **Update `.env` with your credentials:**
   ```bash
   ELASTICSEARCH_URL=https://your-es-host:9200
   ELASTICSEARCH_USER=elastic
   ELASTICSEARCH_PASSWORD=YourSecurePassword
   ELASTICSEARCH_CA_CERT_PATH=/path/to/http_ca.crt
   ```

3. **Set file permissions (Linux/Mac):**
   ```bash
   chmod 600 .env
   ```

4. **Verify the file is git-ignored:**
   ```bash
   git status
   # Should NOT show .env in the output
   ```

## 🔑 API Keys for Threat Intelligence Feeds

### Supported OSINT Feeds

| Service | Environment Variable | Free | Requires |
|---------|----------------------|------|----------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | No | API Key |
| AlienVault OTX | `ALIENVAULT_API_KEY` | Yes | API Key |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Yes (limited) | API Key |
| Demo Feed | N/A | Yes | Demo Mode |

### Configure API Keys in `.env`

```bash
# Get API keys from:
# - VirusTotal: https://www.virustotal.com/gui/home/upload
# - AlienVault OTX: https://otx.alienvault.com/api
# - AbuseIPDB: https://www.abuseipdb.com/api

VIRUSTOTAL_API_KEY=your_virustotal_key_here
ALIENVAULT_API_KEY=your_alienvault_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

## 🛡️ Best Practices

### For Development

1. **Always use `.env` files** - Never hardcode credentials in source code
2. **Use `.env.example`** - Commit this file with placeholder values to guide developers
3. **Rotate credentials regularly** - Change passwords and API keys periodically
4. **Use strong passwords** - At least 16 characters with mixed case, numbers, and symbols
5. **Never commit `.env`** - The file is git-ignored automatically

### For Production

1. **Use Environment Variable Management:**
   ```bash
   # Instead of .env files, use system-level management
   export ELASTICSEARCH_PASSWORD="ProductionPassword"
   export VIRUSTOTAL_API_KEY="production_api_key"
   python3 main.py
   ```

2. **Use Secrets Management Tools:**
   - **Kubernetes Secrets** - If running in Kubernetes
   - **Docker Secrets** - If using Docker Swarm
   - **HashiCorp Vault** - For complex multi-service setups
   - **AWS Secrets Manager** - For AWS deployments
   - **Azure Key Vault** - For Azure deployments

3. **Example with Vault:**
   ```bash
   # Export credentials from Vault at startup
   export ELASTICSEARCH_PASSWORD=$(vault kv get -field=password secret/elasticsearch)
   python3 main.py
   ```

4. **Elasticsearch-specific hardening:**
   ```bash
   # Use TLS certificate validation (enabled by default)
   ELASTICSEARCH_VERIFY_CERTS=1
   
   # Point to trusted CA certificate
   ELASTICSEARCH_CA_CERT_PATH=/etc/elasticsearch/certs/http_ca.crt
   
   # Use strong password for elastic user
   # Min 8 characters, must include numbers and special characters
   ELASTICSEARCH_PASSWORD="ComplexP@ssw0rd!123"
   ```

## ⚠️ Credential Validation

The application validates Elasticsearch credentials at startup:

```
⚠️  WARNING: ELASTICSEARCH_PASSWORD not set in .env file.
   Elasticsearch SIEM forwarding will not work.
   Set ELASTICSEARCH_PASSWORD in your .env file or export it as an environment variable.
```

If credentials are missing, SIEM forwarding is automatically disabled, but the application continues to work in local mode.

## 🔄 Rotating Credentials

### Step 1: Update the service credential
```bash
# For Elasticsearch
curl -X POST "https://localhost:9200/_security/user/elastic/_password" \
  -H "Authorization: Bearer token" \
  -H "Content-Type: application/json" \
  -d "{\"password\": \"NewSecurePassword\"}"
```

### Step 2: Update `.env`
```bash
ELASTICSEARCH_PASSWORD=NewSecurePassword
```

### Step 3: Restart the application
```bash
# Stop the running process
# Restart: python3 main.py
```

### Step 4: Verify connection
```bash
python3 es_diagnose.py
# Expected output: "Elasticsearch reachable: True"
```

## 🚨 If Credentials Are Compromised

1. **Immediately rotate the credential:**
   ```bash
   # Reset Elasticsearch password
   sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b
   ```

2. **Update `.env` with new credential**

3. **Audit logs for unauthorized access:**
   ```bash
   # Check Elasticsearch audit logs
   tail -f /var/log/elasticsearch/elasticsearch.log
   ```

4. **Revoke and regenerate API keys** for external services

5. **Consider re-keying TLS certificates** if CA private key was exposed

## 📖 Related Documentation

- **[README.md](README.md)** - Main project documentation
- **[.env.example](.env.example)** - Environment variable template
- **[REVIEW.md](REVIEW.md)** - Comprehensive project review guide

## 🔗 External Resources

- [Elasticsearch Security Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api.html)
- [OWASP: Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [12-Factor App: Config](https://12factor.net/config)
