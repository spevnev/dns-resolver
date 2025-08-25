# Iterative DNS Resolver CLI

## Usage example

Resolving `example.com` starting from the root nameservers with DNSSEC validation and verbose output.

```shell
$ resolve -v example.com
```

Verbose output broken down step by step:

<details>
    <summary>Fetching <code>.</code> DNSKEYs</summary>
    <p><a href="https://www.iana.org/dnssec/files">Root zone trust anchors</a> contain only KSKs (Key Signing Keys). Validating any record other than DNSKEY requires ZSKs (Zone Signing Keys) to be retrieved first.</p>

```shell
Resolving "." using 192.36.148.17 (.)
Answer:
.                        172800   DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
.                        172800   DNSKEY 257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
.                        172800   DNSKEY 256 3 8 AwEAAbEbGCpGTDrcZTWqWWE72nphyshpRcILdzCVlBGU9Ln1Fui9kkseUOP+g5GLUeVFKdTloeRTA9+EYiQdXgWXmXmuW/nGxZjAikluF/O9NzLVrr5iZnth2xu+F48nrJlAgWWiMNau54NI5sZ3iVQfhFsq2pZmf43RauRPniYMShOLO7EBWWXr5glDSgZGS9fSm6xHwwF+g8D4m8oanjvdCBNxXzSEKS31ibxjLifTfvwCg3y4XXcNW9U6Nu3JmoKUdxqpPPIkBvVQbIz4UO2FwaR13uXC03ALP1Yx2QNSS4SZlcIMtAftQR9wtCiuPWQnFv4jkzWqlhp1Lmf7bcoL9yk=
.                        172800   DNSKEY 256 3 8 AwEAAbauxLSFZ+KSWi2cT6TJbm3d+GIVqb2N1XnDjMsRme0b6JlGp/cvwmM5CaJ5LQ7tG1r7LuTHjYZadtbNk2nZmclq9r4KInS48ungoAZb0gJXVw8IvBTBb1YWQmiBqD285pJuORwTii7DF++nNJJk3i55HJt9SmBI7m7t8nvx7OOY/w0inxg3fLH2uY0SKO8he4FGwMc4Ubiab8N8Yhyhh+FkKKdD/+oAcuGF75PjlSXO460B4MlNLlEcjDEzIsKauRYx4YVgSaNomGhMMFblmXRzgW+1R6ywvm5mC9+omlyyizZp2GJfPwGMezuKSGDndO6CYYEc5/lsRhvBYsGjdPM=
.                        172800   RRSIG  DNSKEY 8 0 172800 1757462400 1755648000 20326 . a/y7JFGTViPkNk0wGIyQF0o84Sf9q3MEKbS9NsUilc/Py1NNT5SP10Az7+yCH3ggoPkX1JSW6nGdjdqm94Tyszh4WMlDb+2eEAUOFZl0wPykyZs3MHy0r0fQ9WQFDswycc7iT8CH2xRDZrYZsBOlowm1ai9PzsBUCBCc6H+vWHfT1KA44er6B4dNIOWTv9/dL7M01HhgR8eiiy1i+e4YIR08k4ErjRKJ0+XawUqJmCZ0V8zdanRq4BHD7rJVnYnECWM1YGL+3PEJEDfXwkSXimUsbcjyCjUE2r2cNYwpQrOSsaRda70OpDCZ8jt+5dmyJCnRRNocaJo5BD62o6w9qA==
```
</details>

<details>
    <summary>Querying <code>.</code> for <code>example.com</code></summary>

```shell
Resolving "example.com." using 192.203.230.10 (.)
Authority:
com.                     172800   NS     a.gtld-servers.net.
com.                     172800   NS     b.gtld-servers.net.
com.                     172800   NS     c.gtld-servers.net.
com.                     172800   NS     d.gtld-servers.net.
com.                     172800   NS     e.gtld-servers.net.
com.                     172800   NS     f.gtld-servers.net.
com.                     172800   NS     g.gtld-servers.net.
com.                     172800   NS     h.gtld-servers.net.
com.                     172800   NS     i.gtld-servers.net.
com.                     172800   NS     j.gtld-servers.net.
com.                     172800   NS     k.gtld-servers.net.
com.                     172800   NS     l.gtld-servers.net.
com.                     172800   NS     m.gtld-servers.net.
com.                     86400    DS     19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A
com.                     86400    RRSIG  DS 8 1 86400 1757264400 1756137600 46441 . SU62OxdtF2cFhsGwICOfoGhxXzzt7FpxbiVMpLGHwoRacnEZoxFTpjRe8cj0GbCyvMvnrwpue4hqNQaQcmZtSWXXk2XcGJH8Vi+8TUOH2tKzBZsfls0Fk50SE5D8DPLUT8+zttxS7oXHHAZ4WNqypaDOpwVglg9kcO8Fa+ObBHOQJxpipISPlAJnHhkVeF/M4O5+O2PNMtG1GPvgtY4v9CK5KeY7fgP91lNpOx5oqHKZOw5rGiwaA7qaRz1T91Vsed97it0+74Sf6f/hu5RcNz+ybsMtkqZJYtVKQLv8kylZYJrGNCtsnHPs2XUUakhBqk8FWjB6xfDzRkBv7L7Qlw==
Additional:
a.gtld-servers.net.      172800   A      192.5.6.30
a.gtld-servers.net.      172800   AAAA   2001:503:a83e::2:30
b.gtld-servers.net.      172800   A      192.33.14.30
b.gtld-servers.net.      172800   AAAA   2001:503:231d::2:30
c.gtld-servers.net.      172800   A      192.26.92.30
c.gtld-servers.net.      172800   AAAA   2001:503:83eb::30
d.gtld-servers.net.      172800   A      192.31.80.30
d.gtld-servers.net.      172800   AAAA   2001:500:856e::30
e.gtld-servers.net.      172800   A      192.12.94.30
e.gtld-servers.net.      172800   AAAA   2001:502:1ca1::30
f.gtld-servers.net.      172800   A      192.35.51.30
f.gtld-servers.net.      172800   AAAA   2001:503:d414::30
g.gtld-servers.net.      172800   A      192.42.93.30
g.gtld-servers.net.      172800   AAAA   2001:503:eea3::30
h.gtld-servers.net.      172800   A      192.54.112.30
h.gtld-servers.net.      172800   AAAA   2001:502:8cc::30
i.gtld-servers.net.      172800   A      192.43.172.30
i.gtld-servers.net.      172800   AAAA   2001:503:39c1::30
j.gtld-servers.net.      172800   A      192.48.79.30
j.gtld-servers.net.      172800   AAAA   2001:502:7094::30
k.gtld-servers.net.      172800   A      192.52.178.30
k.gtld-servers.net.      172800   AAAA   2001:503:d2d::30
l.gtld-servers.net.      172800   A      192.41.162.30
l.gtld-servers.net.      172800   AAAA   2001:500:d937::30
m.gtld-servers.net.      172800   A      192.55.83.30
m.gtld-servers.net.      172800   AAAA   2001:501:b1f9::30
```
</details>

<details>
    <summary>Fetching <code>com</code> DNSKEYs</summary>

```shell
Resolving "com." using 192.48.79.30 (com.)
Answer:
com.                     86400    DNSKEY 257 3 13 tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==
com.                     86400    DNSKEY 256 3 13 8Xtg+1bVIvhjQVPnhcCpeFMup23jnTS7NW09BC4H8p97mSF2zIOs73t46nUEJSA7GPK4Ios83SvH6xPD4wNafg==
com.                     86400    RRSIG  DNSKEY 13 1 86400 1756994555 1755698255 19718 com. IaktpGocPzZnAc9PjdL7zzKQve/RRyPPKxkioFw0Oqt+wg7yHcMri48NrD35Dws4OKTzD7J/qPsBAQ9u60ODkw==
```
</details>

<details>
    <summary>Querying <code>com</code> for <code>example.com</code></summary>

```shell
Resolving "example.com." using 192.5.6.30 (com.)
Authority:
example.com.             172800   NS     a.iana-servers.net.
example.com.             172800   NS     b.iana-servers.net.
example.com.             86400    DS     370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C
example.com.             86400    RRSIG  DS 13 2 86400 1756516349 1755907349 20545 com. yKAzWBzHPSoWLP3w4vQafTPITQRXhpx7uta+L8/Gk7zQwzfQ0un2XnOFLlZh2OtnEVT2VPjp7/OVDX1Zbdpm8A==
```
</details>

<details>
    <summary>Resolving <code>example.com</code> authoritative nameservers</summary>
    <p>The authoritative nameservers for <code>example.com</code> are under the <code>net</code> zone, so the resolution must restart from the root.</p>


<blockquote>
<details>
    <summary>Querying <code>.</code> for <code>b.iana-servers.net</code></summary>

```shell
Resolving "b.iana-servers.net." using 199.7.91.13 (.)
Authority:
net.                     172800   NS     a.gtld-servers.net.
net.                     172800   NS     b.gtld-servers.net.
net.                     172800   NS     c.gtld-servers.net.
net.                     172800   NS     d.gtld-servers.net.
net.                     172800   NS     e.gtld-servers.net.
net.                     172800   NS     f.gtld-servers.net.
net.                     172800   NS     g.gtld-servers.net.
net.                     172800   NS     h.gtld-servers.net.
net.                     172800   NS     i.gtld-servers.net.
net.                     172800   NS     j.gtld-servers.net.
net.                     172800   NS     k.gtld-servers.net.
net.                     172800   NS     l.gtld-servers.net.
net.                     172800   NS     m.gtld-servers.net.
net.                     86400    DS     37331 13 2 2F0BEC2D6F79DFBD1D08FD21A3AF92D0E39A4B9EF1E3F4111FFF282490DA453B
net.                     86400    RRSIG  DS 8 1 86400 1757264400 1756137600 46441 . GSjxfZBbPzp02CJKfTRf+lmL9vX4DeRR0n8BadthmP2vi7xt/RHjS3zB+sa8S9+K4ey9xrBA+1npo7b804v63hBNkMJqoPW3wFwK9BaCV29umdHMQXyHmwd+hk9yz8EjGDwhtVF/4eSKCpdpDN6dpm9bObBTH6gppRzeAnELAsPFCWcBDc6hI57nxNltuIT2kzAgeB5mTxWd7C9sSQphtVbqlgY0vcjyHgTTkcJETzK2BqUs5MLTtCyaH3qBvk9NC8pidvFK/WcPyStDqHX4riNaKL9LZujtu1yqeeO08+s5b4ZGzB9foiIRpfxDfTGQbiHgoj2mOk5Qv5YDSkyVZw==
Additional:
a.gtld-servers.net.      172800   A      192.5.6.30
b.gtld-servers.net.      172800   A      192.33.14.30
c.gtld-servers.net.      172800   A      192.26.92.30
d.gtld-servers.net.      172800   A      192.31.80.30
e.gtld-servers.net.      172800   A      192.12.94.30
f.gtld-servers.net.      172800   A      192.35.51.30
g.gtld-servers.net.      172800   A      192.42.93.30
h.gtld-servers.net.      172800   A      192.54.112.30
i.gtld-servers.net.      172800   A      192.43.172.30
j.gtld-servers.net.      172800   A      192.48.79.30
k.gtld-servers.net.      172800   A      192.52.178.30
l.gtld-servers.net.      172800   A      192.41.162.30
m.gtld-servers.net.      172800   A      192.55.83.30
a.gtld-servers.net.      172800   AAAA   2001:503:a83e::2:30
b.gtld-servers.net.      172800   AAAA   2001:503:231d::2:30
c.gtld-servers.net.      172800   AAAA   2001:503:83eb::30
d.gtld-servers.net.      172800   AAAA   2001:500:856e::30
e.gtld-servers.net.      172800   AAAA   2001:502:1ca1::30
f.gtld-servers.net.      172800   AAAA   2001:503:d414::30
g.gtld-servers.net.      172800   AAAA   2001:503:eea3::30
h.gtld-servers.net.      172800   AAAA   2001:502:8cc::30
i.gtld-servers.net.      172800   AAAA   2001:503:39c1::30
j.gtld-servers.net.      172800   AAAA   2001:502:7094::30
k.gtld-servers.net.      172800   AAAA   2001:503:d2d::30
l.gtld-servers.net.      172800   AAAA   2001:500:d937::30
m.gtld-servers.net.      172800   AAAA   2001:501:b1f9::30
```
</details>

<details>
    <summary>Fetching <code>net</code> DNSKEYs</summary>

```shell
Resolving "net." using 192.42.93.30 (net.)
Answer:
net.                     86400    DNSKEY 257 3 13 HiBoGpzDRAgrDmUXXTSnl7jCX6Hx5bzkU2jSxMbVI01yS+13EyOghnCidBXU0bH2gi2w9GhYGacpU6CrtwoFNg==
net.                     86400    DNSKEY 256 3 13 BwmuZTRDEnF5yIylRPdiibpfukzvMWY569GigcA4DNHHhLWxndFz8tUHIfAyY9AAVdX9hfRoRvnr2OThC4+7Hg==
net.                     86400    RRSIG  DNSKEY 13 1 86400 1756995035 1755698735 37331 net. vYd3jAQqImNWoynNWD1jmAbN9v8J5x7UBPk711DqcaSMcRArLYlMmuWftA30zIbRy6bzPhKdBujmcWXeluAgzw==
```
</details>

<details>
    <summary>Querying <code>net</code> for <code>b.iana-servers.net</code></summary>

```shell
Resolving "b.iana-servers.net." using 192.31.80.30 (net.)
Authority:
iana-servers.net.        172800   NS     ns.icann.org.
iana-servers.net.        172800   NS     a.iana-servers.net.
iana-servers.net.        172800   NS     b.iana-servers.net.
iana-servers.net.        172800   NS     c.iana-servers.net.
iana-servers.net.        86400    DS     7474 8 2 893CC96419BA2F255A8C9BE913753AD2CA7265C67B9D1BAF3CD18AEC4CBFEA9C
iana-servers.net.        86400    RRSIG  DS 13 2 86400 1756521682 1755912682 33296 net. qrb2wZ546RyB3ZP8Z0vX0Z+40ourJ2VpwGFw/guC3loZGquyrA4fnbJ7d9iNakSnh2DVhuWh0SfwcpCf4UUf3A==
Additional:
a.iana-servers.net.      172800   A      199.43.135.53
a.iana-servers.net.      172800   AAAA   2001:500:8f::53
b.iana-servers.net.      172800   A      199.43.133.53
b.iana-servers.net.      172800   AAAA   2001:500:8d::53
c.iana-servers.net.      172800   A      199.43.134.53
c.iana-servers.net.      172800   AAAA   2001:500:8e::53
```
</details>

<details>
    <summary>Fetching <code>iana-servers.net</code> DNSKEYs</summary>

```shell
Resolving "iana-servers.net." using 199.43.135.53 (iana-servers.net.)
Answer:
iana-servers.net.        3600     DNSKEY 256 3 8 AwEAAcRjtfwPjr2xnAVQKlJON0X3ChBBQOtAV3A59BacB9kbVRsowVkjUDsYmUUPtLogmj0grifvhwbDiDw20M9HC8iZWtdAs9WR+5g3eOdVu6FHk3XvgyCaugjm0MRJIQvgVYM9dAHKV4W7Xj9/47BaSkGowjtzYVIeqOpv08ZGQFcr
iana-servers.net.        3600     DNSKEY 257 3 8 AwEAAZEHBKB+ExU5FSYF3DHxrLGzRnAKkYspCRRBsWCP05Ynb7EGqS4NeQdeFEFotkUol9Lf3LgKq0jT9J6rvB7VxjdMMUmi6yi7Dnk/PoKyFYq3KdhArVfFroxldcQtSl4sxZs7l6Orpf3njNPlGTUBrNesg9r75kxx/dRmoiaUJjQPPPWLWRnO5rncBWTk+PfOdSSZ9ntivIu4KGONjXF6ZnKkVWwxwJ5/iK7+EYiSkQqGQLn3Og5scLUUZqTBy0Ju+2MA8PdjOlNUQGlZWRGZu72RKZhKNv3Mv8I4ayDdttY8nPfRF1B+r12578Sj7RXbkUh5k/lfK1nkEeLkVcKKL+E=
iana-servers.net.        3600     DNSKEY 257 3 8 AwEAAeMWp+hSiqwAHLsBhCGUqPXBeh5JZNqaihL2YXiiSFIx0jJHr/+2VNASe1JFWk+ESdV1JKPgxBJai0oXQ+Slz1UUMeSb2A9b6hNaKKZadVcPdosOUma5K+aanGxoxOMi8op5oCFfgyghFND9cSjIsevBaSZ0VwwD2mAUdKQenIDcgFgZ8KbBvX0/zR6UY52c9fd8w6+KG/TXbWgU2dZKxOzPUOdGrQfVtPgUjOoVzbcd0jmMyURu+nwngMWF7gekNalu7h5VY9xS7oTPiUhQ0rbXUSR7J3Pi3JSQZdrfy484u2zy/3I2Axnu784/TVxAzpapz/OQ0geAE6nnSKcxcEE=
iana-servers.net.        3600     RRSIG  DNSKEY 8 2 3600 1757267360 1755481597 7474 iana-servers.net. DdwdrJZOeOsxHCrQP+6z9HElip8C27YPw/Ul8iMmtGN1pxnChvKLdSsDIgrNMwy9qnDIfo0+WRd7vQZmaSv+gb1t3MWAMzmixyAgMs2MBSflXbVFWBhB6W8bjw1g4NWsaSng27Sgih6Q654FEVC6X+loage2bgUQFGvlasH5/EuzZdZiisoJvA7u3+RhaSCGZsKxAEaQp0787GKJXL6MsdgpqnqM5aFs9d5QpxkiJX2Uagp5SUdspAOJSUusuXTbQfOqNhr4zQ0INK4B+VuMBzhWx50trQkfLsfkbPf934VVf/c2lKbHfJzFWq3FqECAMYI7blM9HtUJ2H22XexKXw==
iana-servers.net.        3600     RRSIG  DNSKEY 8 2 3600 1757267360 1755481597 7579 iana-servers.net. rOYxgOCADOIPm4MQ4wrKcw602On2HC8NtV2rRMnmykoqtWxbTA+ZIpwVNltR++Cbj7Q1imoWuUhblxTSpO0oKu3b2UhVI4h96+xv/b2H+ba8Q0OL0FF76zuBVmz771rnUga9tMdf0XFgQFZ0jmFuJpMt1wavR27YRzmuwwcGI1dLQE2zhpFOYYbdjfAYv1TQ5Yp1esQDDZ3IXQ94hTFIpyqkIrC98anoQZcx2ZJdgrC+QHpiT1ZIHPRTp0hoM/fQ4eBS4EH1QMLkYXwQluI0DpcXMn0FF6afuJ2NlZ8bv5/n1uDPlkxhFkmRenIeOwCm4yPwwl0bz0grFkhgflal5A==
```
</details>

<details>
    <summary>Querying <code>iana-servers.net</code> for <code>b.iana-servers.net</code></summary>
    <p>The authoritative nameserver returns the address for <code>b.iana-servers.net</code>. This completes the resolution of the nameservers authoritative for <code>example.com</code>, allowing to finally continue the original resolution.</p>

```shell
Resolving "b.iana-servers.net." using 199.43.133.53 (iana-servers.net.)
Answer:
b.iana-servers.net.      1800     A      199.43.133.53
b.iana-servers.net.      1800     RRSIG  A 8 3 1800 1757108711 1755303856 42210 iana-servers.net. Sz+z1dfzXNuU7r3emp0AmDhOKxWrVCRqh9t/VMLlT9+Ux7GKx9KdTEeE9RPxnLhv7z9Qgr4NquqdQ1c6BHjLXw4NOYUaoAdRvwK2n4sScfI9NgFWFGv4w/s6LT9HYr4/FEO24EziEpVkGHsJunHc4PHLkFNgvRDaWQ0k3bgvWNc=
Authority:
iana-servers.net.        1800     NS     a.iana-servers.net.
iana-servers.net.        1800     NS     b.iana-servers.net.
iana-servers.net.        1800     NS     c.iana-servers.net.
iana-servers.net.        1800     NS     ns.icann.org.
iana-servers.net.        1800     RRSIG  NS 8 2 1800 1757192648 1755332716 42210 iana-servers.net. qavQGQqmAqRfq8EBGwkGaBuccuVcJhR0pUaj/JXp/3/T015WSREfNMgcYW5foPWiLv2VHH9ksfd2/VpVgZ/mVTMQenp7zFL7VeLk62otCYR5s7SyDNleO8qZPY+CrX8Zpa0XJyz9DGmp4oTNh4dmZe72new6HGBh1OUxV88Pel0=
Additional:
a.iana-servers.net.      1800     A      199.43.135.53
a.iana-servers.net.      1800     RRSIG  A 8 3 1800 1757155933 1755361517 42210 iana-servers.net. LC4ieTZk4xfuEjB1o3tdhDfqWyOipHEE/0UWnivfYZuRPXczPipdGsohZUmA2D0/5QIWkmxmoM4K162zM5+tJ8IlDWA1hcfHnQwsKu5CHzkSqg48ZkA3pZ/6uDclqtGyYNdhuJY0T6O23R9o2rbMOmckOD0QAxPh6D5ud6/lAyg=
c.iana-servers.net.      1800     A      199.43.134.53
c.iana-servers.net.      1800     RRSIG  A 8 3 1800 1757426167 1755575200 42210 iana-servers.net. VHuguPYr292kn3sbt6AqbGH+ja8yIYD0/4qsdh8JJJlRFQMcsAbMw4V1pKOtroP6/r+/3vCUGY0OdAX/gZbxQptDqOwiOl3jmu3U1bWgkYqALm3TNigsscCEmqtRoPBnkM0dwdM17UMQ5wqjAEOc1RHazG8mu99zIz+Po6eKzSo=
a.iana-servers.net.      1800     AAAA   2001:500:8f::53
a.iana-servers.net.      1800     RRSIG  AAAA 8 3 1800 1757389255 1755582400 42210 iana-servers.net. CPzPEiP3bHdef9Ml2YTlX8FOlV0diudLh0OuZB8hJ1qzfUZaqOBYuDeJBIwUt1QHF8D7hBUJ0YjaPoYwOtTqPjpkOJlqfqmqNnBgzoKyPZOV0dNN4MVnXtdnq5P3Bimr6Zk7GGTA5PKGN035MBJ6sx2FXjYUnjrWAyNxLDN/9j0=
```
</details>
</blockquote>
</details>

<details>
    <summary>Fetching <code>example.com</code> DNSKEYs</summary>

```shell
Resolving "example.com." using 199.43.133.53 (example.com.)
Answer:
example.com.             3600     DNSKEY 256 3 13 GHMHW23o2fKR8SpBuMZcMEFCwWcnKwg5TmCcPaWx54Y+thK0yMuJQigdp50EdxinZDFocXPt7ExPrtj+oC3nZw==
example.com.             3600     DNSKEY 256 3 13 tdTWdTVCgRLggM25UP45sghawQN5icq8nmJi22M+8+Kn7VBQd3PA5pTqsg4pAfCRskQ6RVShroX9UdRZh4Wq+A==
example.com.             3600     DNSKEY 257 3 13 kXKkvWU3vGYfTJGl3qBd4qhiWp5aRs7YtkCJxD2d+t7KXqwahww5IgJtxJT2yFItlggazyfXqJEVOmMJ3qT0tQ==
example.com.             3600     RRSIG  DNSKEY 13 2 3600 1757703413 1755898090 370 example.com. 7H+ZcbsieSINnFVO/b+LD20ankhbxrWHivSlsQIblqqBRMYkmZS7bE3YeCRwFFWc8Wsk84p8OrBqRtWvt+4L8Q==
```
</details>

<details>
    <summary>Querying <code>example.com</code> for A records</summary>
    <p>The authoritative nameserver answers with signed A records, completing the resolution.</p>

```shell
Resolving "example.com." using 199.43.133.53 (example.com.)
Answer:
example.com.             300      A      23.192.228.80
example.com.             300      A      23.192.228.84
example.com.             300      A      23.215.0.136
example.com.             300      A      23.215.0.138
example.com.             300      A      23.220.75.232
example.com.             300      A      23.220.75.245
example.com.             300      RRSIG  A 13 2 300 1757686903 1755890831 27290 example.com. gFm9vNFPdWzT+B2zm48o9UiqtcAbtB2xjI2i89C4LHyO5HRYHGAbx375mbL2XjkL9yxMTpSg+rpnQDfLiLCHeA==
Authority:
example.com.             86400    NS     a.iana-servers.net.
example.com.             86400    NS     b.iana-servers.net.
example.com.             86400    RRSIG  NS 13 2 86400 1757123010 1755318256 27290 example.com. 2YHe6YiPOnPchF3Beg9xiqjjUMYj4yNxwaOT44Nq9jBtJW7PGYuqHLuWdw5wBuvBu7c32DVq0pn6Rs3WgQo5fQ==
```
</details>

#### Result
```shell
example.com.             300      A      23.192.228.80
example.com.             300      A      23.192.228.84
example.com.             300      A      23.215.0.136
example.com.             300      A      23.215.0.138
example.com.             300      A      23.220.75.232
example.com.             300      A      23.220.75.245
```

## Build & Install

Default installation path is `/usr/local/bin/resolve`.

```shell
make
sudo make install prefix=/usr/local
```

## Dependencies

Only Linux is supported.

- Make >= 4.3
- pkg-config >= 1.8.1
- OpenSSL >= 3.0.14
- g++ >= 15
- libstdc++ (comes with g++) >= 15

## Implemented RFCs
- [RFC1034](https://www.rfc-editor.org/rfc/rfc1034): DOMAIN NAMES - CONCEPTS AND FACILITIES
- [RFC1035](https://www.rfc-editor.org/rfc/rfc1035): DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
- [RFC4033](https://www.rfc-editor.org/rfc/rfc4033): DNS Security Introduction and Requirements
- [RFC4034](https://www.rfc-editor.org/rfc/rfc4034): Resource Records for the DNS Security Extensions
- [RFC4035](https://www.rfc-editor.org/rfc/rfc4035): Protocol Modifications for the DNS Security Extensions
- [RFC5155](https://www.rfc-editor.org/rfc/rfc5155): DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
- [RFC5702](https://www.rfc-editor.org/rfc/rfc5702): Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
- [RFC6605](https://www.rfc-editor.org/rfc/rfc6605): Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
- [RFC6840](https://www.rfc-editor.org/rfc/rfc6840): Clarifications and Implementation Notes for DNS Security (DNSSEC)
- [RFC6891](https://www.rfc-editor.org/rfc/rfc6891): Extension Mechanisms for DNS (EDNS(0))
- [RFC7129](https://www.rfc-editor.org/rfc/rfc7129): Authenticated Denial of Existence in the DNS
- [RFC7873](https://www.rfc-editor.org/rfc/rfc7873): Domain Name System (DNS) Cookies
- [RFC8080](https://www.rfc-editor.org/rfc/rfc8080): Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC
