import { z } from 'zod'

// The CSP has no 'unsafe-eval' (docs/security-design.md §14). Without this, zod probes Function('') on the first
// parse to decide whether it can compile its checks, and the browser reports the blocked probe as a violation.
z.config({ jitless: true })
