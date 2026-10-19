# Lead Qualification Skills

Harvey uses a hybrid qualification approach: BANT for initial screening, enhanced with ICP scoring for prioritization.

---

## BANT Framework (Initial Qualification)

### Budget
- Can they afford the solution?
- Signals: company size, funding stage, job postings for related roles
- Green flags: recently funded, hiring in your product's domain
- Red flags: very small team with no budget indicators

### Authority
- Is this person a decision-maker or influencer?
- Decision-maker titles: VP, Director, Head of, C-suite, Founder
- Influencer titles: Manager, Lead, Senior — can champion internally
- If not the authority: ask for the right person (don't waste sequences)

### Need
- Do they have the problem you solve?
- Signals: tech stack, industry challenges, LinkedIn posts about pain points
- Validate by: checking their current tools, recent job posts, company stage

### Timeline
- Are they likely to buy soon?
- Signals: active evaluation (G2/Capterra reviews), recent vendor changes
- "Not now" is okay — schedule a future touchpoint

---

## ICP Scoring System

Score every prospect 1-10 before outreach:

| Criteria | Points | Details |
|----------|--------|---------|
| **Title match** | 0-3 | Exact ICP title = 3, adjacent = 2, related = 1 |
| **Company fit** | 0-3 | Right industry + size = 3, one match = 2, tangential = 1 |
| **Engagement signals** | 0-2 | Active on LinkedIn = 1, posts about relevant topics = 2 |
| **Reachability** | 0-2 | Verified email = 2, LinkedIn only = 1, no contact = 0 |

### Priority Tiers
- **Score 8-10**: High priority — personalized outreach immediately
- **Score 5-7**: Medium priority — include in batch campaigns
- **Score 3-4**: Low priority — only if pipeline needs volume
- **Score 1-2**: Skip — not worth the outreach

---

## MEDDIC (For Complex Deals — Future Use)

When Harvey handles enterprise prospects or multi-stakeholder deals:

- **Metrics**: What quantifiable outcomes does the buyer care about?
- **Economic Buyer**: Who controls the budget?
- **Decision Criteria**: What factors will they use to decide?
- **Decision Process**: What steps do they go through to buy?
- **Identify Pain**: What's the core problem driving urgency?
- **Champion**: Is there an internal advocate for your solution?

---

## Disqualification Signals

Harvey should NOT pursue prospects who:
- Have fewer employees than the minimum ICP threshold
- Are in a completely unrelated industry
- Have no discoverable contact information
- Already use a deeply entrenched competitor (unless switching signals exist)
- Explicitly opted out of communications

## Enrichment Priorities

When qualifying, gather in this order:
1. Company domain + size (free: LinkedIn, website)
2. Decision-maker name + title (free: LinkedIn search)
3. Email address (free: pattern guessing + SMTP verification)
4. Recent company news (free: Google search)
5. Tech stack (free: BuiltWith, Wappalyzer)
6. Personalization angles (free: LinkedIn posts, company blog)


---

## DevTools & FetchInbox Qualification Framework

For developer tooling and test infrastructure prospects, qualify against concrete technical architecture rather than vague business size.

### Technical ICP Criteria (Tier 1 vs Tier 2)
1. **Tier 1 (High Intent / Architectural Fit)**:
   - AI Agent teams building autonomous browser operators (`BUILDS_AI_OR_BROWSER_AGENTS`).
   - SaaS platforms with email OTP/magic link verification AND automated E2E test suites (`HAS_SIGNUP_OTP_OR_MAGIC_LINK` + `USES_E2E_TEST_FRAMEWORK`).
   - QA consultancies managing multi-tenant test suites (`MULTI_TENANT_QA`).
2. **Tier 2 (Moderate Fit / Potential Need)**:
   - Developers with public APIs and technical docs, but unverified E2E test suite volume.
3. **Disqualified (Instant Rejection)**:
   - Direct competitors (disposable email services, Mailosaur, Mailtrap, temporary inbox providers).
   - Consumer eCommerce / retail with no developer or automation focus.
   - Closed enterprise environments requiring exclusively on-premise air-gapped hardware.

### Evidence Quality Ladder
- **SUFFICIENT**: At least 2 independent verifiable facts (e.g., active QA automation job post + OTP signup flow on site).
- **PARTIAL**: 1 factual technical indicator (e.g., OTP login detected, but test framework unknown). Status MUST remain `POTENTIAL_FIT / NEEDS_REVIEW`.
- **INSUFFICIENT**: Only DNS SPF records or domain name without visible authentication/testing evidence.

### Prohibition on Active Buyer Labeling
A prospect MUST NOT be marked `CONFIRMED_ACTIVE_BUYER` unless concrete, fresh buying intent (e.g., active hiring for test infra, public complaints of flaky email tests, or immediate architecture migration) is verified with independent evidence.
