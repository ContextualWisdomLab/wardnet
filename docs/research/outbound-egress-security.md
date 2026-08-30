# Outbound egress security research

Wardnet's fetch boundary follows two research-backed constraints: destination
authorization must cover resolved addresses, and the authorized address set must
remain bound to the subsequent connection. URL-string filtering alone does not
cover DNS rebinding or redirects.

Jackson et al. describe DNS rebinding as a firewall-circumvention technique and
evaluate policy-based pinning and hostname authorization as deployable defenses.
Wardnet therefore evaluates every resolved address, rejects denied address
classes, and gives each fetch hop a request-local DNS pin board so the HTTP
connection cannot perform a second, different resolution.

Jabiyev et al. show that SSRF defenses are bypassed when validation and the
actual network request are separated, including through changing DNS answers.
Wardnet keeps URL parsing, address-class policy, redirect validation, and the
connect-time address set inside one egress owner. Redirects are disabled in the
HTTP client and followed manually only after a new policy evaluation.

## References

Jackson, C., Barth, A., Bortz, A., Shao, W., & Boneh, D. (2009). Protecting
browsers from DNS rebinding attacks. *ACM Transactions on the Web, 3*(1), 1–26.
https://doi.org/10.1145/1462148.1462150. Author publication
page and manuscript: https://cs.stanford.edu/people/dabo/pubs/abstracts/dnsrebind.html

Jabiyev, B., Mirzaei, O., Kharraz, A., & Kirda, E. (2021). Preventing server-side
request forgery attacks. In *Proceedings of the 36th ACM/SIGAPP Symposium on
Applied Computing* (pp. 1626–1635).
https://doi.org/10.1145/3412841.3442036. Author-hosted manuscript:
https://theseclab.org/publications/sac21.pdf

The papers are linked rather than copied because redistribution rights for the
publisher versions were not established for this repository.
