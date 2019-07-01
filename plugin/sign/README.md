# sign

## Name

*sign* - add DNSSEC records to zone files.

## Description

The *sign* plugin is used to sign (see RFC 6781) zones. In this process DNSSEC resource records
are added. The signatures have a expiration date, so the signing process must be repeated every so
often, otherwise the zone's data will go BAD (RFC 4035, Section 5.5).

Only NSEC is supported, *sign* does not support NSEC3.

It works in conjunction with the *file* and *auto* plugins; this plugin **signs** the zones, *auto*
and *file* **serve** the zones.

For this plugin to work at least one Common Signing Key, (see coredns-keygen(1)) is needed. This key
(or keys) will be used to sign the entire zone. *Sign* does not support the ZSK/KSK split, nor will
it do key rollovers - it just signs.

*Sign* will:

* (Re)-sign the zone with the CSK(s) every Thursday at 15:00 UTC (+/- generous jitter).
* Create signatures that have an inception of -3H and expiration of +3W for every key given.
* Add or replace *all* apex CDS/CDNSKEY records with the ones derived from the given keys. For each
  key two CDS are created one with SHA1 and another with SHA256.
* Update the SOA's serial number to the *Unix epoch* of when the signing happens. This will
  overwrite the previous serial number.

Keys are named (following BIND9): `K<name>+<alg>+<id>.key` and `K<name>+<alg>+<id>.private`.
The keys **must not** be included in your zone; they will be added by *sign*. These keys can be
generated with `coredns-keygen` or BIND9's `dnssec-keygen`. You don't have to adhere to this naming
scheme, but then you need to name your keys explicitly, see the `keys` directive.

The generated zone is written out in a file named `db.<name>.signed`.

When CoreDNS starts up (or is reloaded) a quick check is done to see if the zone needs to be
resigned; this happens by checking SOA's RRSIG expiration time. If within 2 weeks, the zone will be
resigned.

## Syntax

~~~
sign DBFILE [ZONES...] {
    key file|directory KEY|DIR...
    directory DIR
    jitter 5d
}
~~~

*  **DBFILE** the database file to read and parse. If the path is relative, the path from the
   *root* directive will be prepended to it.
*  **ZONES** zones it should be sign for. If empty, the zones from the configuration block are
   used.
*  `key` specifies the keys (it can be specified multiple times) to sign the zone. If `file`
   is used the **KEY** is used as is. If `directory` is used, *sign* will look in **DIR** for
   `K<name>+<alg>+<id>` files.
*  `directory` specifies the **DIR** where CoreDNS should save zones that have been signed.
   If not given this defaults to `/var/lib/coredns`. The zones are saved under the name
   `db.<name>.signed`.
*  `jitter` will be applied to the sign date of 15:00 UTC Thursday, so avoid a stampeding herd of
   zones waiting to be signed. This default to 5 days.

## Examples

Sign the `example.org` zone contained in the file `db.example.org` and write to result to
`/var/lib/db.example.org.signed` to let the *file* plugin pick it up and serve it.

~~~
example.org {
    file /var/lib/coredns/db.example.org.signed
    sign db.example.org {
        key directory /etc/coredns/keys
    }
}
~~~

Or use a single zone file for multiple zones, note that the **ZONES** are repeated for both plugins.
Also note this outputs *multiple* signed output files. Here we use the default output directory
`/var/lib/coredns`.

~~~
. {
    file /var/lib/coredns/db.example.org.signed example.org
    file /var/lib/coredns/db.example.net example.net
    sign db.example.org example.org example.net {
        key directory /etc/coredns/keys
    }
}
~~~

This is the same configuration, but the zones are put in the server block, but note that you still
need to specify what file is served for what zone in the *flie* plugin:

~~~
example.org example.net {
    file var/lib/coredns/db.example.org.signed example.org
    file var/lib/coredns/db.example.net.signed example.net
    sign db.example.org {
        key directory /etc/coredns/keys
    }
}
~~~

## Also See

The DNSSEC RFCs: RFC 4033, RFC 4034 and RFC 4035. And the BCP on DNSSEC, RFC 6781. Further more the
manual pages coredns-keygen(1) and dnssec-keygen(8). And the *file* plugin's documentation.
