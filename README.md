# certific

A single Go binary that shuttles Traefik's `acme.json` between a single-writer
"issuer" Traefik and many "gateway" Traefiks via S3. One image, one binary,
two run modes (`upload` and `download`) selected by the `--mode` flag.

Full quickstart, configuration reference, and operator guide land in a later
commit.
