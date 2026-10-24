# PenteFino Ephemeral Container Runner (`pentefino_runner`)

Asynchronous, secure container runner for ephemeral scanner sandboxing in PenteFino.

## Security Controls
- Read-only root filesystem (`--read-only`)
- Restricted temporary filesystem (`--tmpfs /tmp:rw,noexec,nosuid,size=64m`)
- Dropped Linux capabilities (`--cap-drop ALL`)
- Privilege escalation prevention (`--security-opt no-new-privileges:true`)
- Network isolation (`--network pentefino_pentefino-net` / `pentefino-net`)
- Proxy traffic routing (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`)
- Resource limits (`--cpus 1.0`, `--memory 512m`, `--pids-limit 128`)
- Init process reaping (`--init`)
- Ephemeral container cleanup (`--rm`, and `docker rm -f` on timeout)
