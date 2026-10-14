# How I use AI in my development flow for Strata

While a majority of the code is human written, Claude Opus 5.5 and Sonnet 5.5, as well as Gemini 4 Argon, GPT-6 Astra, and GPT-6 Luna have been used to various degrees within the making of this Project.

- Anthropics models have been primarily used for brainstorming features, managing GitHub publication [as I got zero clue of this git black magic... qmq] and merging trees - say taking my instructions on how I want certain 3AM brainstorm (human-)slop-code implemented, what I missed, and auditing how I "performed" compared to previous coding sessions so I can dynamically understand, learn, and improve on my skillset.

---

- GPT models where used when I ran out of Opus credits! :P

---

- Gemini 3.X was used when I ran out of both Opus *and* GPT tokens, Gemini 4 Argon was used to detect, understand, and act on vulnerabilities. Argon 4 has actually discovered a majority of the recently fixed critical flaws - like RCE through dashboard previews if strangers were able to upload to your servers - and has helped me understand, act on, and learn how to spot and prevent such trivial mistakes in the future.

---

Using AI in programming as a **HELPER** is okay, using it to brainstorm features, or validate UX choices against existing apps, is also okay, however, just taking these results as a finished product is absolutely not okay.

I perform weeks and weeks of manual troubleshooting, analysis, testing, validation, pentesting, brainstorming with others, and correcting the inevitable mistakes an AI **will** make before major releases. AI is a tool, and AI will always be a tool. 