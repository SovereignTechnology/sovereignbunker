export const NOSTR_CONSTANTS = {
  NIP46_KIND: 24133,
  DEFAULT_RELAYS: [
    'wss://relay.nsec.app',
    'wss://relay.damus.io',
    'wss://nos.lol',
  ] as readonly string[],
  /**
   * How often (ms) the bunker watchdog checks relay connection status and
   * re-subscribes any listener whose relay(s) have dropped. Guards against
   * nostr-tools' built-in reconnect failing to recover from abrupt socket
   * errors (it gives up when an `error` fires before a clean `close`).
   */
  RELAY_WATCHDOG_INTERVAL_MS: 30_000,
  /**
   * Only NIP-46 requests created in the last this-many seconds are requested from relays, and the
   * signer ignores any request event older than this. Without a `since`, every re-subscribe made
   * relays hand back their stored kind-24133 events and the bunker answered old requests again.
   * A client clock up to this far behind the relays' still works.
   */
  NIP46_SINCE_WINDOW_S: 600,
  /** The signer ignores request events dated further than this ahead of its own clock. */
  NIP46_FUTURE_SKEW_S: 300,
  /** The replay guard keeps an id this long past the end of the since window after its event's date. */
  NIP46_HANDLED_MARGIN_S: 60,
  /** Upper bound on the request ids the replay guard remembers (all signers together). */
  NIP46_HANDLED_EVENT_IDS_MAX: 20_000,
  /**
   * Self-ping liveness: the signer publishes a kind-24133 to itself on each relay alone and
   * expects it back on that relay's subscription. First round this long after a listener starts,
   * then every interval; a ping not back within the timeout is a miss, and a relay that has
   * echoed before is re-subscribed after this many misses in a row.
   */
  NIP46_SELF_PING_FIRST_MS: 30_000,
  NIP46_SELF_PING_INTERVAL_MS: 180_000,
  NIP46_SELF_PING_TIMEOUT_MS: 20_000,
  NIP46_SELF_PING_MISSES: 2,
} as const;

/**
 * Hold-and-ask approval: a gated request on an `ASK` connection is held for the operator instead of
 * being refused. The client waits for the final reply (BIES waits about 240 s in all), so the hold
 * must end, and the signer must answer, well inside that window.
 */
export const APPROVAL_CONSTANTS = {
  /** How long a held request waits for the operator before it is answered as denied. */
  DEFAULT_TTL_MS: 100_000,
  MIN_TTL_MS: 5_000,
  /** Upper bound so a misconfigured TTL cannot outlive a client's own timeout. */
  MAX_TTL_MS: 200_000,
  /** Token entropy: 24 random bytes = 192 bits, far above the 128-bit floor. */
  TOKEN_BYTES: 24,
  /** Held requests one connection may have open at once; the next is answered as denied. */
  MAX_HOLDS_PER_CONNECTION: 10,
  /** Held requests the whole signer may have open at once. */
  MAX_HOLDS_GLOBAL: 200,
  /** Event content shown to the operator is cut to this many characters. */
  PREVIEW_CONTENT_MAX: 280,
  /** At most this many distinct tag names are shown. */
  PREVIEW_TAG_NAMES_MAX: 20,
} as const;
