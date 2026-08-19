/**
 * Damerau-Levenshtein distance (optimal string alignment variant):
 * insertions, deletions, substitutions, and adjacent transpositions each
 * cost 1. Small inputs only (package names), so the O(n*m) table is fine.
 */
export function damerauLevenshtein(left: string, right: string): number {
  if (left === right) {
    return 0;
  }
  const rows = left.length + 1;
  const cols = right.length + 1;
  const table: number[][] = Array.from({ length: rows }, () => new Array<number>(cols).fill(0));

  for (let row = 0; row < rows; row += 1) {
    (table[row] as number[])[0] = row;
  }
  for (let col = 0; col < cols; col += 1) {
    (table[0] as number[])[col] = col;
  }

  for (let row = 1; row < rows; row += 1) {
    for (let col = 1; col < cols; col += 1) {
      const cost = left[row - 1] === right[col - 1] ? 0 : 1;
      let value = Math.min(
        (table[row - 1] as number[])[col]! + 1,
        (table[row] as number[])[col - 1]! + 1,
        (table[row - 1] as number[])[col - 1]! + cost,
      );
      if (
        row > 1 &&
        col > 1 &&
        left[row - 1] === right[col - 2] &&
        left[row - 2] === right[col - 1]
      ) {
        value = Math.min(value, (table[row - 2] as number[])[col - 2]! + 1);
      }
      (table[row] as number[])[col] = value;
    }
  }

  return (table[rows - 1] as number[])[cols - 1]!;
}
