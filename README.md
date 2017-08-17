# pseudoStarbound

A simple Starbound-compatible server designed to function as a quick-n'-dirty
 fallback.

----

#### About

Running a Starbound server sucks. There are many reasons for this, but one of
 the big ones is instability. This project aims to help with that by providing
 a fallback option for use during maintenance or when the primary server is
 offline.

pseudoStarbound accepts clients on the configured ip:port and immediately kicks
 them with a configured status message. This message is simply stored in a file
 and can be changed on-the-fly without restarting pseudoStarbound. Additionally,
 pseudoStarbound how has RQuery support! It will respond to rquery commands just
 like a real server would (including the obligatory Starbound quirks).

#### Installation

1. Make sure you have python3.5 or higher.
2. Copy the default settings from `config/example.cfg` to `config/config.cfg`
 and edit as needed.
3. Set a plain-text status message in the configured status file.
4. Start the thing.
5. ???
6. Profit.

#### Usage recommendations

* pseudoStarbound should operate on ports other that the ones Starbound or
 StarryPy3k use.
* Traffic should be redirected to pseudoStarbound on an as-needed basis.
 iptables NAT works well enough.
* The status message can be updated on-the-fly. Consider tying it into your
 monitoring/recovery solution.
* pseudoStarbound should be fairly resilient, but consider using the PID file
 to check the process with your existing  monitoring/recovery solution.
