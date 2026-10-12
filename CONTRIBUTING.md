# Contributing to Strata

Thanks for wanting to help. Strata is a small, one-person project, so short and focused pull requests are the easiest to review and merge.

## Try it first

You don't need Caddy, cloudflared or a Cloudflare account to work on Strata. The demo instance runs the full dashboard with a week of made-up traffic:

```bash
git clone https://github.com/Sanedish/strata.git
cd strata
pip install -r requirements.txt
python tests/demo.py
```

Then open [http://127.0.0.1:8290](http://127.0.0.1:8290). You're signed in as the demo user `alex`. Everything lives in a temp folder and uses IP ranges reserved for documentation, so nothing touches your system or a real visitor.

## Before you open a pull request

Run the test suite:

```bash
python tests/run_all.py
```

It builds a throwaway instance with a stub Caddy and needs port 8190 free. Add `--offline` if you have no internet connection. Every suite should pass; if one already fails on `main`, say so in the pull request.

If you change something you can see in the dashboard, add a screenshot from the demo instance.

## How the code is written

- **Plain Python, no framework.** Standard library first. The only dependencies are the four in `requirements.txt`; please ask in an issue before adding one.
- **Vanilla JavaScript, no build step.** The dashboard in `static/` is loaded as-is by the browser.
- **SQLite for everything.** No other database or service.
- **Match the code around your change:** naming, comment density, and the same patterns the file already uses.
- **The interface is a flat operator display:** aligned tables and tiles, no animations, gradients or decorative widgets. Changes to this repository keep that look; see [Forks and the name "Strata"](#forks-and-the-name-strata) for your own copy.
- **Interface text** says what something does in a few words. Error messages say what happened and what to do next, e.g. "Couldn't save: the file changed on disk. Reload to see it." Accounts are always **Owner**, **Administrator**, **Member** or **Moderator**.

[`README.md`](README.md#code-layout) has a map of which file does what.

## Windows first, Linux welcome

Strata is built and used on Windows. The Linux paths (systemd install, file handling) pass the tests but have never run on a real machine. If you run Linux, a report of what works and what breaks is one of the most useful things you can contribute, even without a fix.

## Where to start

- Issues labelled [**good first issue**](https://github.com/Sanedish/strata/labels/good%20first%20issue) are small and self-contained.
- [`ROADMAP.md`](ROADMAP.md) lists what's planned and what's still open.
- For anything bigger than a bug fix, open an issue first so we can agree on the approach before you spend time on it.

## Security issues

Please don't open a public issue for a vulnerability. Report it privately as described in [`SECURITY.md`](SECURITY.md).

## Forks and the name "Strata"

Change your own copy however you like, including the whole interface. That's what the MIT License is for.

If you publish a modified version under the name **Strata**, keep the basic design language:

- Flat, rectangular panels on a strict grid. Panels side by side share their height.
- Plain tables and lists with clear text. No decorative widgets, gradients or filler cards.
- No entrance or exit animations, no pulsing indicators.
- Short, plain wording: say what something does and what to do next.

A version that drops this for a generic, animated "AI dashboard" look is a different project: please give it a different name. You're still welcome to say it's "based on Strata" and link back here.

## License

By contributing, you agree that your contribution is licensed under the [MIT License](LICENSE), like the rest of Strata.
