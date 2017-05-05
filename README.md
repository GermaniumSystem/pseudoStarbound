# pseudoStarbound

A simple Starbound-compatible server designed to function as a quick-n'-dirty fallback.

----

#### About

Running a Starbound server sucks. There are many reasons for this, but one of
 the big ones is instability. This project aims to help with that by providing
 a fallback option for use during maintenance or when the primary server is
 offline.

pseudoStarbound accepts clients on the configured ip:port and immediately kicks
 them with a configured status message. This message is simply stored in a file
 and can be changed on-the-fly without restarting pseudoStarbound.

#### Installation

1. Make sure you have python3.5 or higher.
2. Edit the settings at the top of pseudoStarbound.py. You may be able to get
 away with changing nothing or just the port.
3. Set a plain-text status message in the configured status file.
4. ???
5. Profit.

#### Usage recomendations

* pseudoStarbound should operate on a port other that the Starbound or
 StarryPy3k server.
* Traffic should be redirected to pseudoStarbound when needed. iptables NAT
 works well enough.
* The status message can be updated on-the-fly. Consider tying it into your
 monitoring/recovery solution.
* pseudoStarbound should be fairly resilient, but consider using the
 auto-generated pidfile to check the proccess with your existing
 monitoring/recovery solution.
