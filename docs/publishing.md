# Publishing the dashboard: nginx-proxy-manager and Authelia

The dashboard answers on the LAN at `http://198.51.100.11:8787/` the moment
`deploy.sh` has run. This document is about the other path: a DDNS hostname on
the internet, TLS on it, and a passkey gate in front of it — so the phone can
open the page from anywhere, which is what makes it a dead-man switch rather
than a page you have to be at home to read.

**This is a separate stack, and it is not sentinel's.** `proxy/` holds its own
compose file, its own auth service and its own volumes; nothing in sentinel's
container imports any of it, and `deploy.sh` excludes `proxy/` from the rsync,
so a sentinel deploy cannot ship a second stack's config to the NAS. The two
directions of the dependency are deliberate: sentinel keeps working when this
stack is down (the LAN address above is unaffected), and this stack is entirely
useless without sentinel's `/healthz` and `/api/*` endpoints existing.

Two access rules in the auth service are deliberate holes and are documented in
the runbook below. `tests/test_proxy_config.py` fails if either is deleted, and
says what each one buys.

---

## 1. Prerequisites

- **A DDNS hostname that resolves to your home IP.** The certificate is issued
  for it, it is the WebAuthn relying-party id, and it is the cookie domain, so
  it must be the name the phone actually opens. If it changes, every enrolled
  passkey is bound to the old name and must be enrolled again.
- **A DNS provider API token** for the DNS-01 challenge. The token needs to be
  able to create the `_acme-challenge` TXT record for the name. It is entered
  into nginx-proxy-manager's own UI (step 3) and is not a variable in
  `proxy/.env.example` — NPM keeps its own credentials in its own store.
- **Port 443 forwarded by the router to `PROXY_IPV4` (198.51.100.20).**
- **Port 80 is never opened, and nothing here needs it.** The DNS-01 challenge
  proves control of the name by writing a DNS record rather than by serving a
  file over HTTP, which is the whole reason it was chosen: HTTP-01 would need
  an inbound port 80 open to the internet for nothing but a certificate.

## 2. Deploy

Copy the directory — not the whole repo — and run everything below on the NAS,
from its parent (`/share/CACHEDEV1_DATA/Programs/sentinel`):

```bash
rsync -az proxy/ admin@198.51.100.10:/share/CACHEDEV1_DATA/Programs/sentinel/proxy/
```

On the NAS, `docker` is not on a non-interactive `PATH` (Container Station
installs it under `.qpkg/container-station/bin`); `deploy.sh` carries the
measured path and these commands need it too — either export it, or substitute
it for `docker` throughout:

```bash
docker() { /share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker "$@"; }
cd /share/CACHEDEV1_DATA/Programs/sentinel
```

**The operator's file goes beside the compose file, not at the repo root.**
Compose resolves `.env` from the directory of the first `-f` file, so
`docker compose -f proxy/compose.yml` reads `proxy/.env` and nothing else. The
failure when it is missing is `${DOMAIN:?set this in .env}` — naming a variable,
not a path — which is a slow hour of looking in the wrong file.

```bash
cp proxy/.env.example proxy/.env
chmod 600 proxy/.env
# fill in DOMAIN, and generate the three secrets ON THE NAS, a different one each:
docker run --rm authelia/authelia:4.38.10 \
    authelia crypto rand --length 64 --charset alphanumeric
```

Fill the three `AUTHELIA_*` values into `.env` from that output. Then the user's
password hash, which is also generated on the NAS and also never written into
this repo:

```bash
docker run --rm authelia/authelia:4.38.10 \
    authelia crypto hash generate argon2 --password 'the password you chose'
```

Paste that into `proxy/authelia/users.yml`, replacing the placeholder hash. The
file is a template: a real hash in version control is a credential in version
control, and this tree is a git repo.

Then start it:

```bash
docker compose -f proxy/compose.yml up -d
```

**THEN READ THE LOG. THIS IS A STEP, NOT A HOPE.**

```bash
docker compose -f proxy/compose.yml logs --tail=40 authelia
```

It must show Authelia started with no error. **The offline suite cannot validate
this config at all** — it asserts the text of two access rules and nothing about
Authelia's schema — so a key this version has renamed or removed, or a path it
cannot write, fails here and *only* here, as a container in a restart loop,
while the suite stays green. That silence is why this line is in the runbook
instead of being left to the reader. (The compose file and the configuration
were parsed as valid YAML when they were written. That rules out a syntax error
and nothing else.)

## 3. nginx-proxy-manager

The admin interface is at `http://198.51.100.20:81/` **from the LAN** — NPM
listens on its own macvlan address and the compose file deliberately publishes
no host port, so this is not on the NAS's own interface and must never be
port-forwarded. First run asks for an admin account; create it before anything
else is reachable.

Add a **proxy host**:

- Domain: the DDNS hostname.
- Forward to `198.51.100.11`, port `8787`, scheme `http`.
- SSL: request a **Let's Encrypt certificate with the DNS-01 challenge**,
  selecting the DNS provider and pasting the API token. Turn on *Force SSL*.
  There is no HTTP-01 option here on purpose — see step 1.

Then **forward auth**. The value that goes in the proxy host's forward-auth field
is the Authelia address the compose file actually assigns — `198.51.100.21`, port
`9091`, the verify endpoint — and the redirect target is `$host`, nginx's own
variable for the hostname being requested:

```
http://198.51.100.21:9091/api/verify?rd=https://$host
```

Not the `${DOMAIN}` template from `.env`: that is an `.env` variable, and in
nginx a name it does not know is substituted as **empty**, so the redirect would
silently point at `https://` and send you back to a login page you had already
passed.

It goes in the proxy host's **Advanced** tab, as an internal `location` that
`location /` reaches through `auth_request`. `/api/verify` is Authelia 4.38's
endpoint and **is slated for removal in v5**, which is why this value is filled
in from the step here rather than hardcoded in prose anywhere else.

No special case for `/healthz` is needed on the NPM side, and none should be
added: NPM asks Authelia about every request and **Authelia decides**, per the
rules in `proxy/authelia/configuration.yml`. That is why the two bypasses are in
that file rather than in the proxy's config — one place holds the policy, and
`tests/test_proxy_config.py` reads it.

### The API bypass needs one more line, and it is not obvious

**Authelia matches `access_control.networks` against the first `X-Forwarded-For`
address, falling back to the TCP source.** An `auth_request` subrequest is made
by nginx, so with no such header Authelia sees nginx's own address —
`198.51.100.20`, which is **inside `198.51.100.0/24`** — and the `/api` rule
matches everything, from anywhere. The LAN scoping would then hold in the config
file and nowhere else. So, in the same **Advanced** tab on the proxy host:

```
proxy_set_header X-Forwarded-For $remote_addr;
```

**Then prove it. The snippet above is the instruction; this test is the
authority on whether it works.** Run it from a machine that is **not** on
`198.51.100.0/24` — a phone on cellular, or any host outside the LAN:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
     -H 'X-Forwarded-For: 169.254.1.2' https://${DOMAIN}/api/status.json
```

**It must print `302`. A `200` means the rule matched and the API is public.**
The test exploits the very trust the header relies on: a request claiming to
come from `169.254.1.2` — link-local, not the LAN — must be turned away by the
login redirect.

**If it prints `200`, close the API hole entirely:** delete the `/api` rule from
`proxy/authelia/configuration.yml` and leave `/healthz` as the only bypass. A
hole that cannot be shown to be scoped is not scoped, and the direct
`http://198.51.100.11:8787/api/status.json` path in step 5 keeps working without
it. Say here that it was closed and why — and expect the suite's "exactly two
rules bypass authentication" check to fail from then on, deliberately: that is
the guard reporting the decision, not a test to bend back.

## 4. Enroll the passkey

Open `https://<hostname>` and sign in once with the password from `users.yml`;
Authelia then offers to register a second factor. Register **Face ID** where you
will actually use it — a passkey enrolled in Safari on the phone is the one the
phone offers, and one enrolled only on the laptop is not. Then, on the phone,
**Add to Home Screen**: the installed app opens standalone with the icon, and
the passkey is what it offers on the next open.

## 5. Verify the two holes

Both are deliberate and both are load-bearing. Check them here, by hand, because
nothing in the offline suite can:

```bash
# The health probe answers with no session at all. One line, naming whether the
# collector is fresh -- it must NOT redirect to a login page.
curl -s https://<hostname>/healthz

# The API answers JSON, not an HTML login page, from a LAN address.
curl -s https://<hostname>/api/status.json | head -5
```

Run both from **a machine on the LAN other than the NAS itself**. The NAS cannot
reach its own macvlan (hairpin — the same reason `deploy.sh --status` curls from
the Mac), so a curl run from a NAS shell fails for a reason that has nothing to
do with either hole, and that reading would be wrong in the alarming direction.

The direct path is worth one check of its own, from the same machine, because it
is what survives this stack failing:

```bash
curl -s http://198.51.100.11:8787/api/status.json | head -5
```

## 6. The accepted risk, stated rather than buried

**The public hostname is a new dependency in the path of the only dead-man
switch.** If this stack fails — NPM down, Authelia down, certificate expired —
the page is unreachable, and from a phone that is indistinguishable from a dead
collector. The `/healthz` bypass is what keeps the two separable, and it
mitigates the confusion without removing the dependency.

This runbook is the **operational** copy, for whoever is fixing it. The
authoritative statement of the trade belongs with the design's other accepted
risks: `docs/architecture.md`, *Accepted risks, stated rather than fixed*.

---

## The auth service's state, and its backup

The enrolled passkey registrations live in a named volume (`authelia-data`),
mounted at `/data` in the container, not in this checkout and not inside the
read-only config mount. Find where it actually is with:

```bash
docker volume inspect proxy_authelia-data
# the project name comes from the compose file's directory, so if that name is
# not found:  docker volume ls | grep authelia
```

Back up that directory, and keep `AUTHELIA_STORAGE_ENCRYPTION_KEY` from `.env`
with it: the key encrypts the registrations, so a backup without the key is not
a backup. Losing both costs a passkey re-enrolment (step 4) and nothing else —
no fleet data lives here, and sentinel's own store is a different volume with a
different owner.
