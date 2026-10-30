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
   * Only NIP-46 requests created in the last this-many seconds are requested from relays.
   * Without a `since`, every watchdog re-subscribe made relays hand back their stored
   * kind-24133 events and the bunker answered old requests again. Generous enough to
   * tolerate client clock skew.
   */
  NIP46_SINCE_WINDOW_S: 600,
  /** Upper bound on the request event ids remembered by the replay guard. */
  NIP46_HANDLED_EVENT_IDS_MAX: 5_000,
} as const;
