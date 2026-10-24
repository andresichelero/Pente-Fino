# PenteFino Forward Egress Proxy & Traffic Control Plane

The Traffic Control Plane intercepts scanner traffic (`HTTP_PROXY` / `HTTPS_PROXY`), enforces immutable scope rules, performs hierarchical rate-limiting via Valkey Lua token buckets, cloaks scanner signatures, redacts sensitive tokens, and captures forensic evidence uploaded to SeaweedFS S3.
