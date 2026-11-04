/// <reference types="bun" />

interface Env {
  TURNSTILE_SECRET?: string;
  PSI_API_KEY?: string;
}

declare namespace Cloudflare {
  interface Env {
    TURNSTILE_SECRET?: string;
    PSI_API_KEY?: string;
  }
}
