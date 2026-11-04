# common-passwords.txt — source and attribution

Local list of common passwords, checked when a password is set. It is never sent anywhere, and
no external service is queried. Details and update policy: `docs/security-design.md` §12.1.

## The dataset

- **Origin:** "Ten Million Passwords" by Mark Burnett (xato.net), 2015.
- **Author's statement:** "a data set of ten million usernames and passwords that I am releasing
  to the public domain".
  <https://web.archive.org/web/20150211131735/https://xato.net/passwords/ten-million-passwords/>
- **Note:** the site's footer carries a general CC BY-SA 3.0 notice for its content, while the
  article states the public domain release of the dataset specifically. Attribution is kept
  here in any case: Mark Burnett (xato.net).

This list contains passwords only, with no usernames.

## The distribution it was taken from

- **Project:** SecLists, <https://github.com/danielmiessler/SecLists>
- **Commit:** `35d74839e66f44d116e694369d86a5bf07aaed6f`
- **File:** `Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt`
- **SHA-256:** `424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51`

The MIT license below covers SecLists as a project. It is not treated as defining the rights in
the individual dataset, which are described above.

## Processing

Reproducible with `scripts/build-password-list.sh`:

1. Keep entries of at least 12 characters (the minimum password length).
2. Remove lines containing `@`.
3. Convert to lowercase, remove duplicates, sort (`LC_ALL=C`).

Result: 46,045 entries, SHA-256
`2ce4934bf860d3d348a9f4ea646df42e8e65c292c734f0633635148c53a73e86`.

## SecLists license

```text
MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
