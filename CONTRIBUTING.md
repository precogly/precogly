# Contributing to Precogly

Thanks for wanting to help build Precogly! We're glad you're here. :)

For detailed setup instructions and architecture docs, head over to our
[full documentation site](https://precogly.github.io/precogly/contributing/).

## 🦉 Owl's Orders\*

- **Human review is non-negotiable.** Every PR needs a real human to review all code before
  submitting. AI-generated code is welcome, but a person is always accountable. "The buck
  stops with the human". This includes commit messages and GitHub ops: you write them, not your AI.
- **Frontend changes need proof.** If your PR touches the UI, include screenshots
  (or a short screen recording) showing what changed. Manual testing is required before
  requesting review.
- **Move slow and don't break things.** A single wrong decision can cause downstream
  effects in a large codebase like Precogly. Deliberate before you generate.
- **Don't over-engineer.** Avoid letting your AI build a Rube Goldberg machine. Keep your AI on a tight leash. Simple beats bloated.
- **Plan before you generate.** Before writing any code, draft a plan for the change you're making. Ask: _"What could this break? What are the unintended side effects?"_ And read every line before submitting. If you can't explain it, you're not ready to submit it.

## Library packs

Contributions of library packs (new packs or changes to existing ones) go to
[precogly/library-packs](https://github.com/precogly/library-packs), not to this repository.

## Contributor License Agreement

Before your first PR can be merged, you'll need to accept our
[Contributor License Agreement](https://gist.github.com/vikram-s-narayan/725cfa57e6e7e68852f1589c321a3bf9).
It's short, written in plain English, and CLA Assistant will prompt you automatically on
your first pull request.

## PR Titles

We use [conventional commits](https://www.conventionalcommits.org/) for PR titles. This drives our automated changelog and release process.

Format: `type: short description`

- `feat:` — new feature (bumps minor version)
- `fix:` — bug fix (bumps patch version)
- `docs:` — documentation only
- `chore:` — maintenance, CI, deps
- `refactor:` — code change that neither fixes a bug nor adds a feature

Examples:
- `feat: add OT/ICS threat library pack`
- `fix: remove Demo category from catalog dropdown`
- `docs: update contributing guide`

## Quick Checklist Before You Open a PR

- [ ] PR title follows the conventional commit format above
- [ ] Code runs locally without errors
- [ ] Frontend changes include screenshots in the PR description
- [ ] You've tested the happy path AND at least one edge case
- [ ] You can explain what your code does and why

## Questions?

Open an issue or start a discussion. There are no silly questions here, only silly answers
(and we try to avoid those too).

Happy coding!

---

\*Precogly's mascot is an owl.

---

And finally ... an ai-generated but human verified limerick to brighten your day :)

_A contributor who coded with flair,_

_Let AI help, but reviewed with care._

_"Plan first," they would say,_

_"Check side effects today,"_

_And their PRs got merged without prayer._
