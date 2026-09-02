# Ansible Security Repair

A Docker-hosted web app for uploaded Ansible playbooks. It runs `ansible-lint` and Checkov, gives their findings to an authenticated Antigravity CLI session for semantic repair, rescans the repaired playbook, then runs it against Docker. It stops after success or five cycles.

## Workflow

1. Upload one UTF-8 `.yml` or `.yaml` Ansible playbook (maximum 500 KB).
2. `ansible-lint` and Checkov scan the uploaded playbook. Their findings are shown live in the browser.
3. Antigravity receives the playbook plus those scanner findings. It repairs them without suppressing checks or changing the playbook's intended result.
4. Both scanners run again. Remaining or new findings go into the next repair cycle.
5. Once static checks are clean, `ansible-playbook -i localhost, --connection local` executes the playbook inside the app container. Docker-oriented Ansible modules use the mounted Docker socket.
6. Ansible/Docker failures are returned to the same Antigravity repair conversation. The repaired playbook is rescanned before each new execution.

The UI shows scanning, individual Checkov and ansible-lint findings, repair, rescan, execution, success, and failure as they happen. A repaired playbook can be downloaded at completion.

## Start

1. Copy `.env.example` to `.env` only if your Docker socket is not at `/var/run/docker.sock`.
2. Start the service:

   ```bash
   docker compose up --build -d
   ```

3. Complete Antigravity OAuth once:

   ```bash
   docker compose exec --user appuser iac-repair agy
   ```

   Choose Google OAuth and complete the CLI's first-run setup.
4. Open `http://localhost:8080` and upload a playbook.

## Security boundary

Mounting `/var/run/docker.sock` gives the app effective control over the Docker host. Uploaded Ansible may also contain arbitrary local tasks, which execute inside the application container. Use trusted playbooks only, and preferably run this stack against a dedicated Docker VM or host. A single uploaded playbook is supported; playbooks that depend on separate roles, inventories, vault files, templates, or collections must include or otherwise make those dependencies available before execution.
