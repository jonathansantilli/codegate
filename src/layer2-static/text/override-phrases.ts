/**
 * Instruction-override phrases matched against normalized (NFKC, hidden
 * characters stripped, confusable-folded, lowercased) text. This is the
 * high-signal literal tier; semantic analysis belongs to the Layer 3
 * meta-agent. Data-driven so a content feed can extend it.
 */
export interface OverridePhrase {
  phrase: string;
  language: string;
}

export const OVERRIDE_PHRASES: readonly OverridePhrase[] = [
  { phrase: "ignore previous instructions", language: "en" },
  { phrase: "ignore all previous instructions", language: "en" },
  { phrase: "disregard previous instructions", language: "en" },
  { phrase: "disregard prior instructions", language: "en" },
  { phrase: "skip permissions", language: "en" },
  { phrase: "bypass permissions", language: "en" },
  { phrase: "bypass safety", language: "en" },
  { phrase: "disable guardrails", language: "en" },
  { phrase: "ignora las instrucciones anteriores", language: "es" },
  { phrase: "ignore las instrucciones anteriores", language: "es" },
  { phrase: "ignore as instrucoes anteriores", language: "pt" },
  { phrase: "ignore as instruções anteriores", language: "pt" },
  { phrase: "ignore les instructions precedentes", language: "fr" },
  { phrase: "ignore les instructions précédentes", language: "fr" },
  { phrase: "ignorez les instructions précédentes", language: "fr" },
  { phrase: "ignoriere alle vorherigen anweisungen", language: "de" },
  { phrase: "ignoriere die vorherigen anweisungen", language: "de" },
  { phrase: "игнорируй предыдущие инструкции", language: "ru" },
  { phrase: "игнорируйте предыдущие инструкции", language: "ru" },
  { phrase: "忽略之前的指令", language: "zh" },
  { phrase: "忽略以上指令", language: "zh" },
  { phrase: "忽略先前的指示", language: "zh" },
  { phrase: "以前の指示を無視して", language: "ja" },
  { phrase: "これまでの指示を無視", language: "ja" },
] as const;
