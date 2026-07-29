FROM python:3.12-slim

# Security: run as non-root, no network by default (we attach `--network=none`
# or `--network=host` at runtime based on SANDBOX_NETWORK).
RUN useradd --create-home --uid 1000 sandbox
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# Pre-install the libraries the agent is most likely to need:
#   * requests     -> hit Wazuh APIs when network=host
#   * pandas       ->aggregate / pivot alert data
#   * jsonschema    ->validate parsed payloads inside the sandbox
#   * pyyaml        ->parse YAML configs / playbooks
#   * jq-style libs optional - the LLM writes python instead of shelling out
RUN pip install --quiet \
        requests urllib3 \
        pandas \
        jsonschema \
        pyyaml

WORKDIR /home/sandbox/work
USER sandbox

# Default command is overridden by the executor:
#   docker run ... python /home/sandbox/work/script.py
CMD ["python", "/home/sandbox/work/script.py"]
