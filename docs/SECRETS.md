# Secrets Management Policy

- Use environment variables for dev; see `.env.template`.
- Never commit real secrets. Use a secret manager in staging/prod.
- Rotate API keys regularly and scope least privilege.
- Encrypt at rest and in transit; prefer managed KMS.
- Audit and restrict access to logs and databases.