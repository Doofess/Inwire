/**
 * How much key log the app takes in (ADR 0073). Plain constants, so main's
 * follower and the renderer's store read the same numbers.
 *
 * `KEYLOG_CAP_BYTES`: a followed or loaded file larger than this brings in only
 * its newest part, from `size - cap`, starting at the first whole line.
 * `MAX_KEYLOG_SECRETS`: the store holds at most this many secrets; a line past
 * it is counted in `stats().dropped` and not kept.
 */
export const KEYLOG_CAP_BYTES = 536_870_912;
export const MAX_KEYLOG_SECRETS = 4_194_304;
