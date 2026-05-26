# Lesson 01: The Pain

**Why 3 million SSH attacks per day needs a real solution.**

---

## The Problem

You just rented your first VPS. `ping` works. `ssh` works. Life is good.

Then you check `journalctl -u ssh | grep "Failed password"`:

```
Mar 12 02:14:23 vps sshd[1234]: Failed password for root from 1.2.3.4 port 51234 ssh2
Mar 12 02:14:25 vps sshd[1234]: Failed password for root from 5.6.7.8 port 42356 ssh2
Mar 12 02:14:27 vps sshd[1234]: Failed password for invalid user admin from 9.10.11.12 port 33456 ssh2
Mar 12 02:14:29 vps sshd[1234]: Failed password for root from 13.14.15.16 port 24567 ssh2
Mar 12 02:14:31 vps sshd[1234]: Failed password for root from 1.2.3.4 port 51235 ssh2
```

This repeats every 3 seconds. 24/7. From hundreds of different IPs.

**This is not a bug. This is the steady state of the internet.**

Every public SSH port gets attacked. Not sometimes — constantly. Bots scan the entire IPv4 space every few hours. If you have port 22 open, you **will** get hit.

---

## Why Existing Solutions Fail

### 1. fail2ban

fail2ban is the default answer. It watches logs, counts failures, and adds iptables rules.

**Problems:**
- Reacts **after** the damage (takes 3-5 failed attempts)
- `iptables` is being replaced by `nftables` — fail2ban's nftables support is immature
- Single-threaded — under heavy attack it falls behind
- No threat intelligence — treats every IP as equally suspicious
- No persistence — restart fail2ban and it forgets everything
- No API — you can't query "what IPs are blocked right now?"

### 2. Cloud WAF (Cloudflare, AWS Shield)

**Problems:**
- Requires routing traffic through them (adds latency)
- Costs money — even basic plans are $20+/month
- Doesn't protect non-HTTP services (SSH on non-standard ports)
- You don't own your security

### 3. Manual iptables blocks

```bash
iptables -A INPUT -s 1.2.3.4 -j DROP
```

**Problems:**
- Manual = too slow
- Attackers rotate IPs faster than you can type
- You're asleep when the attack happens

---

## What We Actually Need

| Requirement | Why |
|-------------|-----|
| **Real-time** | Block within milliseconds, not minutes |
| **Intelligent** | Know which IPs are dangerous (threat intel) |
| **Self-protecting** | Survive attacks against itself |
| **Persistent** | Remember across restarts |
| **Isolated** | Don't depend on other tools — own your stack |
| **API-first** | Query, control, monitor programmatically |
| **Privacy-first** | No phone-home in the free tier |
| **One-line deploy** | `curl ... | sudo bash` |

---

## The Approach

Instead of wrapping existing tools, we build **our own agent** that:

1. Watches `auth.log` / `journald` in real time
2. Scores each attacking IP (behavioral + threat intelligence)
3. Blocks attackers **immediately** via nftables
4. Notifies you via Telegram/Email
5. Protects itself from tampering
6. Remembers everything across restarts
7. Gives you CLI + HTTP control

And in future phases:
8. Shares threat hashes with other agents (P2P)
9. Pulls global intel from a cloud feed
10. Gives you a dashboard

---

## The Mindset

This course is not about copying code. It's about learning to think like a security engineer:

- **Every design decision is a trade-off** (speed vs memory, simplicity vs features)
- **Start minimal, then spiral back** (we build v0.1 first, then discover what's missing)
- **Own your stack** (no black-box dependencies)
- **Privacy is not optional** (the free tier must have zero phone-home)

---

## Check Your Understanding

Before moving on, you should be able to answer:

1. Why is fail2ban insufficient for a busy VPS?
2. What's the difference between "blocking" and "intelligent blocking"?
3. Why does the agent need to be self-protecting?
4. What's the value of persistence across restarts?

If you can answer these, you're ready for [Lesson 02](../02-first-line/).
