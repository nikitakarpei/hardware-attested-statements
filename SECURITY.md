# Security policy

Report vulnerabilities privately, not in a public issue: **Security → Report a vulnerability** on this repository,
or email nikitakarpei@mailbox.org. Include how to reproduce it (a bundle, policy or test is ideal).

**In scope**: this repository and its releases, including flaws in the format itself, even where the verifier
follows the spec. **Out of scope**: the services the format relies on (time-stamp authorities, drand, hardware
vendors), unless the verifier mishandles what they publish, and the limits the spec's trust model (section 7)
states, unless they are worse than it says.

We acknowledge reports within 7 days, assess them within 14, and aim to fix within 90, with the disclosure date
agreed with you. Fixes are announced in a GitHub security advisory (with a CVE where one applies) and the
changelog; reporters are credited unless they prefer not to be.

Only the latest release is supported.
