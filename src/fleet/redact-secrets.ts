/**
 * Strips secret values out of text before it leaves the machine.
 *
 * A finding's evidence is the line that caused it, and for a credential
 * finding that line IS the credential: `"ANTHROPIC_API_KEY": "sk-ant-…"`. The
 * scanner is right to show the developer that line on their own terminal. The
 * server is a different audience. It needs to know which key was set and where,
 * never what it was — the whole content-collection policy exists to keep
 * credentials off the console, and a finding that carries the key in its
 * evidence walks straight past it.
 *
 * Two passes. Known token shapes are masked wherever they appear, because a key
 * is a key whatever it is labelled. Then any value sitting under a name that
 * means "secret" is masked, because the shapes list is never complete. Values
 * that are clearly placeholders — `${VAR}`, `${{ secrets.X }}`, `<your-key>` —
 * are left alone: they are not secrets, and redacting them would hide the very
 * pattern a workflow finding is pointing at.
 */

export const REDACTED = "[redacted]";

/** Token formats that identify themselves by prefix or structure. */
const SHAPES: readonly RegExp[] = [
  // Anthropic, OpenAI, Stripe and friends: sk-…, sk-ant-…, sk-proj-…, sk-or-v1-…
  /\bsk-[A-Za-z0-9_-]{8,}/gu,
  // GitHub: classic and fine-grained.
  /\bgh[opsur]_[A-Za-z0-9]{20,}/gu,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/gu,
  // GitLab, npm, PyPI, Hugging Face.
  /\bglpat-[A-Za-z0-9_-]{20,}/gu,
  /\bnpm_[A-Za-z0-9]{36}\b/gu,
  /\bpypi-[A-Za-z0-9_-]{20,}/gu,
  /\bhf_[A-Za-z0-9]{20,}/gu,
  // Slack.
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/gu,
  // AWS access key ids and Google API keys.
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\bAIza[0-9A-Za-z_-]{35}\b/gu,
  // age identities.
  /\bAGE-SECRET-KEY-1[A-Z0-9]{20,}/gu,
  // JWTs: three base64url segments, the first always decoding to `{"`.
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/gu,
  // Bearer credentials in a header, whatever scheme minted them.
  /(\bBearer\s+)[A-Za-z0-9._~+/=-]{16,}/giu,
  // PEM private keys, body and all.
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
];

/**
 * A name that means the value beside it is a secret.
 *
 * Matched against the key in `key: value`, `key = value`, `"key": "value"`
 * and `KEY=value` forms, in JSON, YAML, TOML, dotenv and prose alike.
 */
const SECRET_NAME =
  /(api[_-]?key|secret|token|password|passwd|credential|authorization|private[_-]?key|access[_-]?key)/iu;

/**
 * `<name><separator><value>` where the separator is `:` or `=`, with optional
 * quoting on either side. An auth scheme word after the separator — `Bearer`,
 * `Basic`, `Token` — belongs to the separator, not the value: it names how the
 * credential is presented, and is the part worth keeping. The value runs to the
 * closing quote or to the next delimiter. Keeps the name and separator; only
 * the value is replaced.
 */
const NAMED_VALUE =
  /(["']?)([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|password|passwd|credential|authorization|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*)(\1\s*[:=]\s*(?:(?:Bearer|Basic|Token)\s+)?)(["']?)([^"'\s,;}\]]+)\4/giu;

/** Values that describe where a secret comes from rather than being one. */
function isPlaceholder(value: string): boolean {
  return (
    value.startsWith("$") || // ${VAR}, ${{ secrets.X }}, $ENV
    value.startsWith("<") || // <your-key-here>
    value.startsWith("{{") || // templating
    /^(true|false|null|none|redacted|\[redacted\])$/iu.test(value) ||
    value.length < 4
  );
}

/** Text with every secret value replaced by REDACTED; the labels stay. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const shape of SHAPES) {
    out = out.replace(shape, (match, keep: unknown) =>
      typeof keep === "string" ? `${keep}${REDACTED}` : REDACTED,
    );
  }
  out = out.replace(
    NAMED_VALUE,
    (match, q1: string, name: string, sep: string, q2: string, value: string) => {
      // Already masked by the shapes pass: the value here is REDACTED with its
      // closing bracket left outside the match.
      if (!SECRET_NAME.test(name) || isPlaceholder(value) || value.startsWith("[redacted")) {
        return match;
      }
      return `${q1}${name}${sep}${q2}${REDACTED}${q2}`;
    },
  );
  return out;
}
