Foreword
--------

This project is considered mature software, so it has not been changed in
a long while. However it is not dead in that I still care about it and
would handle bug reports usually in a matter of days, or at worst within
a few weeks.

As of 2023, I still use this daemon daily for dynamic DNS update and
low-priority monitoring, and it has been working well for me for more than
a decade.

The reference repository is based on [fossil][] and available at
<http://fossil.instinctive.eu/ddns>.

[fossil]: http://www.fossil-scm.org/index.html/doc/trunk/www/index.wiki

Introduction
------------

The basic problem this software intend to solve is the notification of a
DNS server by a client with a dynamic IPv4 address. If I did not have my
own DNS, services from `dyndns.org` or `no-ip.org` or stuff like that would be
adapted, but as I run my own DNS I feel it would be lighter, safer, and
more satisfying not to depend on third-party services.

I will assume we have a full access to a box which runs a DNS for the
`domain mydomain.example`, and its hostname is `server` or
`server.mydomain.example`.

The client is a box running in a private network, connected to the internet
through a dumb, proprietary and undocumented NAT router, whose public IP
address can be changed at any time depending on the whims of the ISP. This
is a common situation here in France.

The problem is to have a DNS record `clientname.mydomain.example` on the
server, pointing to the client's current public IP address.

The usual tool for remote DNS updates is `nsupdate`, however I am not
satisfied with it, mainly because of two issues:

 * the client can change anything in the DNS zone, not only its own record,
 * the client has to somehow find out its own IP address before updating.

There used to be a third point in that I do not like pre-shared secrets,
especially in a protocol involving public-key cryptography (both the server
and `nsupdate` need the private key). I since realized that when the client
is compromised, the attacker can do anything the client could do anyway,
and when the server is compromised, the attacker can already do anything
to the DNS, but they can not do anything to the client because it does not
take any action. So using a public-key system would not be an improvement
over a pre-shared secret.

The first issue could be worked around by having the server delegate to
itself a `clientname.mydomain.exmaple` zone for each client. The client could
still do much more than I like, but at least the rest of `mydomain.exmaple`
or other client's zones can not be reached. That is still to heavy and not
secure enough for my taste.

The second issue has to be worked around either by reverse-engineering a
part of the NAT router to extract its public IP address, or by asking some
box on the internet. That seems to be the purpose of
<http://checkip.dyndns.org/>.

So at first I thought about adding a similar page to the web server on my
DNS box. Then I imagined what would be going on: the client asking its
public IP address to the server, and then handing back the address to the
same server for DNS update. That sounds like a waste of resources, why not
simply having the client send a message to the server, and the server using
the remote address embedded in the message to update the DNS record?

That is how this project began: writing a client sending messages once in
a while, and a server listening to this message and updating the records
accordingly, maybe through a `nsupdate` call. This way there is no need for
the client to find out its public IP address, it involves only a single
packet per update, and the client cannot update anything besides its own
`A` record.

That is exactly what this project does, when operating in "unsafe" mode. It
is unsafe because no matter what kind of message you craft, if the client
does not know its public IP address, any attacker can intercept the message
and send it as-is on their behalf, thus injecting their IP into one of my
DNS records. And actually this is exactly what I want to happen, except
with the NAT router instead of an attacker.

Please not however that I do not think it is that unsafe. At least, it is
not less safe than querying `checkip.dyndns.org`: if the attacker can intercept
my message packet, they can intercept HTTP packets for `checkip.dyndns.org`
and return whatever they want.

Still, one might want to be safe against that kind of attack. Assuming the
client can safely find out its own address, it can be embedded into the
message to operate in "safe" mode. It is safer because the IP address that
ends up in the record cannot be changed after the packet is crafted.

However when you are in a situation where "safe" mode can be used, you
might want to use something else than this project. For example, in that
case the only remaining drawback to `nsupdate` is that the client can do
whatever it wants with the zone. Another example is that since the client
knows its address, it knows when it changes, so it can send updates to the
server only when needed, which allows for a heavier update mechanism, e.g.
SSH'ing to the server and running an ad-hoc script there.


Implementation
--------------

The messages contain:

 * a timestamp, to prevent replay attacks and to drop late packets for an
   old IP,
 * the client hostname, used to know which record should be update and to
   get the matching secret,
 * the client IPv4 address, which is set to 0.0.0.0 in "unsafe" mode,
 * a HMAC to sign the rest of the message with the client's secret.

These messages are sent using UDP, because the idea is to send them quite
often (e.g. every few minutes) but it does not matter that much when a few
of them are lost or are not in time. This allow a relatively fast reaction
from the server while still being light in ressource usage.

The actual binary implementation of the message is:

 * first the timestamp as a number of seconds since Epoch (UNIX time)
   written as a decimal integer, followed by a zero byte,
 * then the client hostname, followed by a zero byte,
 * then four bytes of the address, in big endian (i.e. the IP would be
   output using `"%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]`),
   followed by a zero byte,
 * finally the 20 bytes of HMAC-SHA-1 of everything before, followed by
   the tag "sha-1" (without ending zero byte).
