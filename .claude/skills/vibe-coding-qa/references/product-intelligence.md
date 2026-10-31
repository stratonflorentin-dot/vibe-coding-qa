# Product Intelligence and Build Strategy

Use this optional mode before committing substantial build effort, when a user presents a product idea/design/specification, asks if it is worth building, requests competitor or market research, or wants research translated into a build plan. It complements the codebase and launch QA workflows; it does not replace them. Do not force deep market research onto a narrow implementation request unless the user asks for it.

Read `product-research-report-template.md` when preparing a structured deliverable. Adapt the depth and sections to the user's question, product category, target markets, evidence available, and time/budget constraints.

## 1. Select a research mode

- **Quick scan:** identify product/category, users and job-to-be-done, a small set of credible analogues, key uncertainties, and a practical next validation step. Clearly label as preliminary.
- **Focused study:** research one or more named markets, competitors, customer problems, business models, technical feasibility, or regulations.
- **Deep strategy:** combine market, competitor, failure, customer, commercial, technical, regulatory, and development-roadmap analysis. Cover relevant regions and languages, not a token list of countries.
- **Build blueprint:** convert confirmed requirements and evidence into a development-ready MVP and validation plan. Do not start implementation unless asked.

If no mode is named, first extract the product, identify high-impact unknowns, and propose a right-sized scope. Ask only questions that materially change customer, region, monetization, architecture, data, safety, or regulatory conclusions; otherwise proceed with explicit assumptions.

## 2. Understand the product inputs

Inspect supplied text, images, screenshots, files, designs, URLs, and accessible repositories using available tools. Extract visible or documented details; do not infer hidden dimensions, functionality, demand, or implementation from appearance alone. For an existing repository, distinguish implemented behavior from README claims, roadmap items, and proposed features. Respect user-provided access boundaries and do not execute unknown code merely to inspect it.

Maintain three separate lists:

- **Confirmed:** directly stated by the user or verifiable in supplied artifacts.
- **Assumed:** plausible working assumptions, each labelled and revisable.
- **Unknown:** facts needing research, customer validation, or user input.

Record product purpose, problem, users/buyers, geographies, workflow, requirements, constraints, resource/time limits, current alternatives, pricing/business model, technical dependencies, sensitive data, and unique asks. Use `references/product-research-report-template.md` for an intake table when useful.

## 3. Build a research plan

- Scope regions by customer location, purchasing power, regulation, language, distribution, and product fit. Do not claim global coverage after checking only familiar markets.
- For relevant regions, consider North America, Europe, Asia-Pacific, Middle East, Africa, and Latin America; research only those that materially fit the product, and explain exclusions.
- Translate key search terms when a target market uses another language. Preserve the original terms and state where machine translation may weaken interpretation.
- Cover first-party product/company material, independent reporting/analysis, official public records/regulation, technical/academic work, and customer/developer evidence when relevant.
- Prioritize sources according to the claim: company pricing/product status from current official pages; legal duties from official regulators or legislation; failure causes from filings, company statements, and credible independent reporting; customer pain from reviews/discussions with context.
- Record the query/topic, source, source type, publication date, event date if different, access/research date, region, and claim it supports. Use direct links. Distinguish search-result discovery from actually inspected source content.
- Search for counterevidence and competing explanations. A product launch or market-growth report alone does not prove demand, profitability, or a viable opportunity.
- Never claim to have searched the entire internet or accessed unavailable, private, or paywalled content. Record gaps and source-access limits.

## 4. Map competitors and alternatives

Classify relevant products as direct competitors, indirect approaches, substitutes, adjacent products, open-source alternatives, emerging offerings, or discontinued/failed offerings. Avoid padding the list with weakly related companies.

Compare the most relevant options on customer/job, geography, positioning, evidence-backed features, target buyer, pricing and date/region, distribution, integrations, strengths, limitations, complaints, status, and switching/adoption costs. Label information as unknown when no reliable evidence exists. Popularity is not proof of profit or satisfaction.

Use a small, defensible comparison set and explain how it was selected. Treat competitor websites as first-party claims; corroborate material assertions independently where possible. Never recommend copying protected code, confidential material, brand identity, or distinctive proprietary design.

## 5. Investigate customer need and industry failures

- Separate the company's advertised value from user-observed experience, repeated complaints, feature requests, workarounds, cancellation reasons, and purchasing evidence.
- Describe the evidence sample and its selection bias; a handful of reviews or forum posts cannot represent a whole market. Do not scrape private spaces or identify individual reviewers unnecessarily.
- Search for shutdowns, restructures, bankruptcies, failed launches, poor retention, weak unit economics, expensive acquisition/operations, security incidents, supply/distribution issues, regulatory barriers, provider dependency, and expansion failures.
- For each material case, record what happened and when, evidence, documented cause versus analyst inference, company response, applicability to the proposed product, and a mitigation or validation action.
- Use confidence labels: **Verified** (authoritative or multiple independent sources support the claim), **Reported** (credible source reports it but independent confirmation is limited), **Inferred** (reasoned analysis, not reported fact), **Uncertain** (insufficient or conflicting evidence). Attribute claims; never fabricate confidential causes.

## 6. Estimate opportunity and commercial viability

Use published market estimates only when their definition, geography, date, and method fit the question. Reconcile conflicting estimates rather than averaging incompatible numbers. Avoid repeating unsourced TAM figures from pitch decks as fact.

When useful, construct a transparent bottom-up range:

- **TAM:** eligible global customer units × plausible annual value per unit.
- **SAM:** the portion reachable under chosen segment, geography, regulation, and product scope.
- **SOM:** a time-bounded share constrained by sales capacity, channels, adoption, competition, and delivery capacity.

Show input sources, equations, currency/year, assumptions, and sensitivity to major variables. Use ranges when inputs are uncertain; say “not enough evidence” where defensible inputs cannot be found. Do not imply that a market-size calculation predicts the startup's revenue.

Compare relevant revenue models (subscription, usage, transaction, licensing, services, marketplace, advertising, hardware/software, API, or hybrid). Analyze price evidence, who pays, purchasing cycle, acquisition/retention, gross-margin drivers, variable/fixed costs, support burden, third-party fees, and break-even drivers. Only calculate scenarios from explicit assumptions; never invent financial results or guarantee profitability.

## 7. Assess technical and operational feasibility

- Map product requirements to system components, data flows, integrations, hosting, identity, payments, hardware, AI/ML, support, analytics, and operational ownership as relevant.
- Compare at least two viable implementation options when the choice materially affects cost, risk, team fit, or scale. Evaluate total lifecycle cost and migration/lock-in, not popularity alone.
- Verify current API/provider capabilities, license/terms, quotas, data residency, failure modes, pricing, support lifecycle, and security requirements from primary docs where possible.
- Identify unknown dependencies, performance bottlenecks, safety/privacy risks, reliability needs, accessibility, maintainability, and recurring operational work.
- Clearly separate demonstrated feasibility (working prototype/test), documented capability, and untested assumption. Do not imply that a competitor's undocumented architecture is known.

## 8. Check regulation and IP by jurisdiction

Map likely topics and official authorities for the product's actual markets: privacy/data protection, children, consumer protection, payments/financial services, health, transport, communications, product safety/certification, environmental rules, employment, and intellectual property. Verify against current legislation/regulators and date the finding. Explain the product-specific question that requires qualified legal or regulatory review. Do not present this skill's research as legal advice or a compliance certification.

For patents and IP, search official databases where relevant and distinguish a preliminary landscape search from a legal freedom-to-operate opinion. Do not declare a design “unpatented” or legally safe based on a quick web search.

## 9. Synthesize a competitive product plan

Translate findings into:

- A precise target buyer/user, unmet job, value proposition, and positioning.
- A feature opportunity matrix linking competitor coverage, customer evidence, implementation effort, dependencies, risk, and differentiation.
- A scoped MVP: must-have, parity/competitive necessity, differentiator, later, and explicitly out of scope.
- At least one alternative product/technical strategy when evidence is uncertain.
- A staged roadmap: discovery/validation, prototype, MVP, pilot, launch, and scale, each with exit criteria and measurable evidence.
- A validation plan using appropriate interviews, usability studies, concierge/pilot delivery, prototype testing, pricing tests, or landing-page experiments. State what result would change the recommendation; do not present vanity metrics as proof.
- A go / revise / no-go recommendation based on evidence and key assumptions, not an arbitrary average score.

If scores are requested, define what a high value means for every dimension. For example, high customer pain and differentiation may be favorable, while high competitive intensity, development complexity, and regulatory burden are adverse. Give a rationale and confidence for each; the scorecard is a discussion aid, not a scientific probability.

## 10. Produce an evidence-linked report

Use `references/product-research-report-template.md`. Cite major factual claims close to the claim, link original sources, and include publication/event dates when available. Tag conclusions as fact, reported claim, assumption, analysis, or recommendation. Present conflicting evidence, confidence, limitations, missing sources, and research date. Keep verified information separate from recommendations; never fabricate companies, customer comments, market numbers, financials, or technical internals.

After research, summarize the decision and highest-value next experiments. Only move into product build or change an existing app when the user asks; research findings are inputs, not automatic implementation approval.

## Source inspiration

The broader skill also uses a lightweight staged approach: baseline-aware engineering checks, evidence-first investigation, bounded agent roles, realistic UI stress cases, and explicit API read/write contracts. See `references/research-and-advanced-qa.md` for the upstream projects and safeguards. This research mode adds product strategy rather than replacing the original vibe-coding and pre-launch QA mission.