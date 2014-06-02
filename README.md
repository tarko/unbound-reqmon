unbound-reqmon
==============

Constantly monitors local unbound requestlist and tries to find abusive domains that fill up the requestlist. Such attacks use throwaway domains with NS records pointing to victim IP and bots issuing requests for randomized subdomains.

It's meant to be used in cluster/anycast type of setups with multiple recursive servers, when domain is found and blocked on one server, it's also signalled to all other servers.


Example config
==============

block_threshold defines how many different pending requests for domain must there be in the requestlist for domain to be labelled abusive (they must also make up at least block_threshold_pct % of the queue). This obviously creates race condition if you get attacked using two domains simultaneously but better safe than sorry.

It is also good idea to whitelist TLDs/domains that are important to you and you must set notification address for email notifications that are sent when new domain is blocked (monitor this as there might be false positives).

```
{
 "debug": false,
 "block_threshold": 1000,
 "block_threshold_pct": 80,
 "whitelist": "(google\\.com|\\.ee|edgesuite\\.net)$",
 "cluster": [
  "1.2.3.4",
  "2.3.4.5",
  "3.4.5.6",
  "4.5.6.7"
 ],
 "email_recipients": [
  "foo@bar.net"
 ]
}
```

Caveats
=======
Must be run with sufficient permissions to invoke unbound-control. Don't run as root, DRb is not terribly safe!

License
=======
MIT License.  Copyright 2014 Tarko Tikan.
