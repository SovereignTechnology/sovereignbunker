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
