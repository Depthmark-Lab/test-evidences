# The evidence kit as an image, for CI systems other than GitHub Actions
# (Azure DevOps, the microVM lane). GitHub Actions uses the same code through
# action.yml, so both paths run identical collectors and core.
#
# Pin the base image by digest in real use.
FROM python:3.12-slim

RUN useradd --system --uid 10001 --create-home evidence
COPY evidence /opt/evidence
USER 10001

# Other CI systems mount their own settings file and point EVD_SETTINGS at it:
# identity "file", their Vault auth path, their JFrog OIDC provider.
ENTRYPOINT ["python3", "/opt/evidence/cli.py"]
CMD ["list"]
