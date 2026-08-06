/** Type machinery for the message catalogs.
 *
 * `en.ts` is written `as const`, which gives every leaf a literal string type.
 * A translation typed directly against `typeof en` would therefore be required
 * to repeat the English text verbatim — the opposite of the point. DeepStringify
 * widens every leaf back to `string` while keeping the tree shape, so
 * `satisfies Messages` on each locale file enforces exactly what we want:
 * same keys, any words. A missing or misspelled key in any of the 15
 * translations is a compile error in `npm run build`, which is the whole reason
 * these are TS modules rather than JSON.
 */
export type DeepStringify<T> = {
  [K in keyof T]: T[K] extends string ? string : DeepStringify<T[K]>
}
