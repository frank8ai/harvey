"""The signal vocabulary Harvey proposes, and the user confirms.

Harvey never decides on its own what makes a good prospect. It proposes a
catalog of signals it knows how to collect — each with a plain-language
description, what it costs, and why it might matter — and the user confirms,
edits, or rejects them in the dashboard before any collection runs.

Only ``confirmed`` signals get collected. That keeps spend intentional and
keeps the resulting cohorts explainable: a prospect list is a query over
signals a human chose, not a black box.

Design note: every signal is recorded as an OBSERVATION (a row), never a
column. A new signal needs no migration, history comes free, and confidence
and provenance travel with the fact.
"""

# category: discovery | profile | people | verification
# value_type: num | text | bool
# cost_note: what collecting it actually costs, in plain language
CORE_SIGNAL_CATALOG: list[dict] = [
    # ── Discovery: who exists, and how visible are they ──
    {
        "code": "SERP_RANK",
        "label": "Search rank position",
        "description": (
            "Where the business ranks for its core '<service> <city>' search. "
            "The most useful prospecting signal there is: positions 11-30 are "
            "the sweet spot — visible enough to be trying, not winning yet. "
            "Top 10 are already winning (harder sell); 31+ are cheaper but "
            "less motivated."
        ),
        "category": "discovery",
        "value_type": "num",
        "collector": "discover",
        "cost_note": "~$0.0006 per search (paid SERP API, queued endpoint)",
        "confidence_floor": 0.0,
    },
    {
        "code": "FOUND_IN_SERP",
        "label": "Discovered via search",
        "description": "The business appeared in a target-market search — how Harvey found it at all.",
        "category": "discovery",
        "value_type": "text",
        "collector": "discover",
        "cost_note": "included in the search above",
        "confidence_floor": 0.0,
    },

    {
        "code": "NO_WEBSITE",
        "label": "No website at all",
        "description": (
            "The business has a listing and a phone number but no site. If you "
            "sell websites this is the highest-intent signal that exists — and "
            "it is a filter you can query for directly, not something you infer."
        ),
        "category": "discovery",
        "value_type": "bool",
        "collector": "discover",
        "cost_note": "included in the business listing lookup",
        "confidence_floor": 0.0,
    },
    {
        "code": "UNCLAIMED_LISTING",
        "label": "Unclaimed Google listing",
        "description": (
            "Nobody has claimed their Google Business Profile, so they are not "
            "managing how they show up locally. Strong signal for anyone "
            "selling local marketing."
        ),
        "category": "discovery",
        "value_type": "bool",
        "collector": "discover",
        "cost_note": "included in the business listing lookup",
        "confidence_floor": 0.0,
    },
    {
        "code": "REVIEW_RATING",
        "label": "Review rating",
        "description": (
            "Their average star rating. Useful in both directions: a low "
            "rating is a reputation problem to solve, a high one with few "
            "reviews is proof they are good but invisible."
        ),
        "category": "discovery",
        "value_type": "num",
        "collector": "discover",
        "cost_note": "included in the business listing lookup",
        "confidence_floor": 0.0,
    },
    {
        "code": "REVIEW_COUNT",
        "label": "Number of reviews",
        "description": (
            "How many reviews they have. A rough proxy for size and for how "
            "much attention they pay to their online presence."
        ),
        "category": "discovery",
        "value_type": "num",
        "collector": "discover",
        "cost_note": "included in the business listing lookup",
        "confidence_floor": 0.0,
    },

    # ── Profile: what they are (free — HTML Harvey already fetches) ──
    {
        "code": "INCUMBENT_AGENCY",
        "label": "Has a marketing/web agency",
        "description": (
            "An agency credited in the site footer ('Website by X'). High-value: "
            "it tells you who you're displacing, and every detection builds a "
            "roster you can target as a whole book of business. Only recorded "
            "when the credit wording is explicit — a wrong incumbent is worse "
            "than none."
        ),
        "category": "profile",
        "value_type": "text",
        "collector": "profile",
        "cost_note": "free (homepage HTML)",
        "confidence_floor": 0.75,
    },
    {
        "code": "RUNNING_GOOGLE_ADS",
        "label": "Running Google Ads",
        "description": "Google Ads tag on the site — they are spending on acquisition TODAY. Strong budget signal.",
        "category": "profile",
        "value_type": "bool",
        "collector": "profile",
        "cost_note": "free (homepage HTML)",
        "confidence_floor": 0.0,
    },
    {
        "code": "RUNNING_META_ADS",
        "label": "Running Meta/Facebook Ads",
        "description": "Meta Pixel on the site — actively spending on paid social.",
        "category": "profile",
        "value_type": "bool",
        "collector": "profile",
        "cost_note": "free (homepage HTML)",
        "confidence_floor": 0.0,
    },
    {
        "code": "TECH_STACK",
        "label": "Website platform / tools",
        "description": "What the site is built on and which tools it runs (WordPress, Shopify, HubSpot, chat widgets, booking tools).",
        "category": "profile",
        "value_type": "text",
        "collector": "profile",
        "cost_note": "free (homepage HTML)",
        "confidence_floor": 0.0,
    },
    {
        "code": "NO_SCHEMA_MARKUP",
        "label": "Missing structured data",
        "description": "No JSON-LD schema markup — a concrete, checkable SEO gap you can name in an email.",
        "category": "profile",
        "value_type": "bool",
        "collector": "profile",
        "cost_note": "free (homepage HTML)",
        "confidence_floor": 0.0,
    },
    {
        "code": "NO_ONLINE_BOOKING",
        "label": "No online booking/scheduling",
        "description": "No booking or scheduling widget detected — leads have to phone in, so after-hours demand is lost.",
        "category": "profile",
        "value_type": "bool",
        "collector": "profile",
        "cost_note": "free (homepage HTML)",
        "confidence_floor": 0.0,
    },
    {
        "code": "SITE_PAGE_COUNT",
        "label": "Site size",
        "description": "Page count from sitemap.xml. A very thin site suggests little investment; a large stale one suggests neglect.",
        "category": "profile",
        "value_type": "num",
        "collector": "profile",
        "cost_note": "free (sitemap.xml)",
        "confidence_floor": 0.0,
    },
    {
        "code": "BLOG_STALE",
        "label": "Content gone stale",
        "description": "No new content in a long time — content marketing started and abandoned.",
        "category": "profile",
        "value_type": "num",
        "collector": "profile",
        "cost_note": "free (sitemap.xml)",
        "confidence_floor": 0.0,
    },
    {
        "code": "BLOCKS_AI_CRAWLERS",
        "label": "Blocks AI crawlers",
        "description": "robots.txt blocks AI crawlers — they'll be invisible in AI search answers.",
        "category": "profile",
        "value_type": "bool",
        "collector": "profile",
        "cost_note": "free (robots.txt)",
        "confidence_floor": 0.0,
    },
    {
        "code": "HIRING_ROLE",
        "label": "Hiring for a relevant role",
        "description": "An open role on their careers page that implies they're buying in your category right now.",
        "category": "profile",
        "value_type": "text",
        "collector": "profile",
        "cost_note": "free (careers page)",
        "confidence_floor": 0.0,
    },

    # ── People: who decides ──
    {
        "code": "CONTACT_FOUND",
        "label": "Named contact found",
        "description": "A named person scraped from the team/about page, with their title.",
        "category": "people",
        "value_type": "text",
        "collector": "people",
        "cost_note": "free (team page)",
        "confidence_floor": 0.0,
    },
    {
        "code": "DECISION_MAKER_TITLE",
        "label": "Decision-maker title",
        "description": "Title matches an owner/decision-maker pattern (Owner, President, Practice Manager, Marketing Director).",
        "category": "people",
        "value_type": "text",
        "collector": "people",
        "cost_note": "free (team page)",
        "confidence_floor": 0.0,
    },
    {
        "code": "REGISTRY_VERIFIED",
        "label": "Confirmed in a public registry",
        "description": (
            "The person was confirmed in an authoritative public registry "
            "(licensing board, professional registry). Also filters out "
            "scraping artifacts — a name that matches nothing usually wasn't a person."
        ),
        "category": "people",
        "value_type": "text",
        "collector": "people",
        "cost_note": "free (public registry API)",
        "confidence_floor": 0.0,
    },
    {
        "code": "LIKELY_OWNER",
        "label": "Likely the owner",
        "description": "Registry indicators suggest this person owns the business rather than working there.",
        "category": "people",
        "value_type": "bool",
        "collector": "people",
        "cost_note": "free (public registry API)",
        "confidence_floor": 0.0,
    },

    # ── Verification ──
    {
        "code": "EMAIL_PATTERN",
        "label": "Company email pattern",
        "description": "The domain's address format (first.last@, flast@). One real address cracks the whole company.",
        "category": "verification",
        "value_type": "text",
        "collector": "verify",
        "cost_note": "free, or ~1 lookup credit",
        "confidence_floor": 0.0,
    },
    {
        "code": "EMAIL_STATUS",
        "label": "Email deliverability",
        "description": "Whether the address is verified, catch-all/risky, an unverified guess, or invalid.",
        "category": "verification",
        "value_type": "text",
        "collector": "verify",
        "cost_note": "1 verification credit (free tiers available)",
        "confidence_floor": 0.0,
    },
    {
        "code": "CONTACT_FORM_URL",
        "label": "Contact form available",
        "description": (
            "A contact form on the site. Worth knowing because it reaches the "
            "business without needing an email address at all — and roughly "
            "half of domains can't be email-verified."
        ),
        "category": "verification",
        "value_type": "text",
        "collector": "profile",
        "cost_note": "free (site HTML)",
        "confidence_floor": 0.0,
    },
]


# ── DevTools & Qualification Extensions (W1-03) ──────────────────────
DEVTOOLS_SIGNAL_CATALOG: list[dict] = [
    # 6 Fact / Context Observations
    {
        "code": "HAS_SIGNUP_OTP_OR_MAGIC_LINK",
        "label": "Signup/login uses email OTP or magic link",
        "description": (
            "Signup or authentication flow specifically requires an email verification code "
            "or magic link, creating a concrete need for email inbox automation during testing."
        ),
        "category": "profile",
        "value_type": "bool",
        "collector": "devtools",
        "cost_note": "free (login/signup HTML inspection)",
        "confidence_floor": 0.80,
    },
    {
        "code": "USES_E2E_TEST_FRAMEWORK",
        "label": "Uses E2E test framework",
        "description": (
            "Company uses Playwright, Cypress, Selenium, or Puppeteer for browser automation "
            "or end-to-end testing, indicating an automated testing infrastructure."
        ),
        "category": "profile",
        "value_type": "text",
        "collector": "devtools",
        "cost_note": "free (public repository, blog, or job posting analysis)",
        "confidence_floor": 0.85,
    },
    {
        "code": "BUILDS_AI_OR_BROWSER_AGENTS",
        "label": "Builds AI or browser agents",
        "description": (
            "Product or engineering teams build autonomous web agents, computer-use agents, "
            "or headless workflows that require automated email verification on behalf of users."
        ),
        "category": "profile",
        "value_type": "bool",
        "collector": "devtools",
        "cost_note": "free (product documentation and SDK analysis)",
        "confidence_floor": 0.85,
    },
    {
        "code": "HAS_DEVELOPER_DOCS_OR_API",
        "label": "Has developer documentation or public API",
        "description": (
            "Company provides public developer documentation, SDKs, or an API reference, "
            "confirming technical maturity and developer focus."
        ),
        "category": "profile",
        "value_type": "bool",
        "collector": "devtools",
        "cost_note": "free (site navigation and docs path inspection)",
        "confidence_floor": 0.90,
    },
    {
        "code": "USES_TRANSACTIONAL_EMAIL_ESP",
        "label": "Transactional email provider configured",
        "description": (
            "DNS SPF records or headers identify a dedicated transactional email provider "
            "(Postmark, SendGrid, Resend, Mailgun, Amazon SES). Technical signal only, "
            "does not prove active buying intent."
        ),
        "category": "profile",
        "value_type": "text",
        "collector": "devtools",
        "cost_note": "free (DNS SPF/TXT inspection)",
        "confidence_floor": 0.70,
    },
    {
        "code": "HIRING_QA_OR_AGENT_INFRA",
        "label": "Hiring QA or AI agent infrastructure",
        "description": (
            "Active, non-expired job postings for QA automation engineers, SDETs, "
            "or AI agent platform engineers, representing immediate hiring and tooling pressure."
        ),
        "category": "profile",
        "value_type": "text",
        "collector": "devtools",
        "cost_note": "free (careers page inspection)",
        "confidence_floor": 0.80,
    },
    # 2 Derived Qualification States
    {
        "code": "VERISIG_EVIDENCE_SUFFICIENCY",
        "label": "Verisig evidence sufficiency assessment",
        "description": (
            "Derived judgment on whether observations provide sufficient, non-conflicting "
            "evidence across multiple independent sources (SUFFICIENT, PARTIAL, INSUFFICIENT, CONFLICTING)."
        ),
        "category": "verification",
        "value_type": "text",
        "collector": "qualification",
        "cost_note": "free (deterministic qualification engine evaluation)",
        "confidence_floor": 1.0,
    },
    {
        "code": "VERISIG_DISQUALIFIED_REASON",
        "label": "Verisig disqualification reason",
        "description": (
            "Derived disqualification status reason (e.g., DIRECT_COMPETITOR, CONSUMER_ONLY, "
            "NO_AUTOMATION_NEED, ENTERPRISE_CUSTOM_OUT_OF_SCOPE, STALE_BUSINESS)."
        ),
        "category": "verification",
        "value_type": "text",
        "collector": "qualification",
        "cost_note": "free (deterministic qualification engine evaluation)",
        "confidence_floor": 1.0,
    },
]

# Full combined catalog: preserves all 23 core signals + 8 DevTools/Qualification signals
SIGNAL_CATALOG: list[dict] = CORE_SIGNAL_CATALOG + DEVTOOLS_SIGNAL_CATALOG


async def seed_signal_catalog(state) -> int:
    """Register the catalog as PROPOSED signals awaiting user confirmation.

    Idempotent, and never overrides a decision the user already made: an
    existing signal keeps its confirmed/rejected status.
    """
    for sig in SIGNAL_CATALOG:
        await state.upsert_signal_code(
            sig["code"],
            label=sig["label"],
            description=sig["description"],
            category=sig["category"],
            value_type=sig["value_type"],
            collector=sig["collector"],
            cost_note=sig["cost_note"],
            confidence_floor=sig.get("confidence_floor", 0.0),
        )
    return len(SIGNAL_CATALOG)
