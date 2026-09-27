/**
 * The cuts a snaplen is measured at, shared by the two scripts that take them.
 *
 * A header-only capture and the common "headers and a bit": `snaplen.ts`
 * measures each against tshark, and `revisit.ts` rebuilds every frame of each
 * from its record. Its own module because both of those run `main()` at
 * module scope, and importing a value from one would run it.
 */
export const SNAPLENS = [64, 128] as const;
