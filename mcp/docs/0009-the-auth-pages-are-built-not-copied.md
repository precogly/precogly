# 0009: The authorization pages are built, not copied

Status: superseded by [0015](0015-consent-is-a-page-of-the-application.md), which
moves consent into the SPA; the "Moving consent into the SPA" rejection was amended
2026-08-28
Date: 2026-08-11
Relates to: [0004](0004-where-the-user-authorizes.md)
Supersedes: the drift trade-off in [0004](0004-where-the-user-authorizes.md)

The server-rendered pages in the authorization flow are styled by a stylesheet
Tailwind builds from the application's own design tokens, against the Django
templates as its source of class names. They are not hand-written CSS.

## Context

[0004](0004-where-the-user-authorizes.md) decided these pages should look like Precogly,
and accepted a trade-off to get there: "Two templates to keep in step with the frontend.
They live in the Django app and will drift from the React application, because nothing
links them." The alternative it weighed was implementing consent in the SPA, judged to
cost more than the drift.

The drift arrived before the feature did. Styling them by hand meant reading Tailwind
classes off `frontend/src/pages/Login.tsx` and the shadcn primitives and compiling them
into CSS by eye — `max-w-md` became `max-width: 28rem`. Three defects came out of one
sitting:

- a `prefers-color-scheme` dark mode, in a product that is light-only. Nothing mounts a
  `ThemeProvider`; `next-themes` is a dependency whose only import is inside
  `components/ui/sonner.tsx`. On a dark-mode machine the flow went light, dark, light.
- a translucent `bg-muted/30` with no opaque background under it, so the page composited
  over whatever the browser painted.
- a palette copied from `index.css` at a point in time, with nothing to keep it current.

The third option neither 0004 nor the hand-styling considered: the shadcn components are
`cn()` class-string wrappers with no behaviour. What is worth reusing from them *is* the
class strings. Reusing those needs a stylesheet, not a component runtime.

## Decision

Tokens move to `frontend/src/theme.css`, imported by both the application's `index.css`
and a new `frontend/src/auth.css`. The latter builds with `source(none)` and
`@source "../../backend/templates"`, so Tailwind emits only what those templates use —
16KB — and the templates carry the class strings copied verbatim out of
`components/ui/*.tsx`.

```text
  theme.css  ──┬──>  index.css  ──>  vite  ──>  the application
   (tokens)    │
               └──>  auth.css   ──>  tailwindcss CLI  ──>  backend/static/css/auth.css
                        ▲                                        │
                        └── @source: backend/templates ───────────┘
```

Form widgets are the exception. Django renders that markup, so the template cannot put
classes on it; the input and label strings are applied by element in `auth.css`.

Four templates are overridden because a user meets them inside a flow: the login page,
the consent screen, the connected-applications list, and the revoke confirmation.
django-oauth-toolkit's own `base.html` is overridden too, in one line, because it links
Bootstrap 2.3.2 from a CDN that no longer resolves — that reparents every remaining page
in the package onto the same shell.

## Rejected

- **Mounting React into the Django pages**, hydrated from `json_script`, with
  django-oauth-toolkit still owning the form POST. True component reuse with the security
  path untouched. Rejected for what it costs at the point of use: ~150KB of JavaScript to
  render a two-field form, on the most security-sensitive page in the product.

- **Moving consent into the SPA.** Still worth revisiting, on the trigger 0004 named —
  consent carrying product logic rather than styling.

  *Amended 2026-08-28: the cost stated here was wrong.* Issuing the authorization code
  does not move off django-oauth-toolkit. `AuthorizationView.form_valid` marshals form
  fields into a `credentials` dict and ends in a single `OAuthLibMixin` call,
  `create_authorization_response()` (`views/mixins.py:101`); the GET side is
  `validate_authorization_request()` (`:92`). Two DRF views over those two methods leave
  oauthlib minting the code, `save_authorization_code` writing the `Grant`, and PKCE,
  `redirect_uri`, `resource` and scope validation in `oauth2_validators.py` untouched.

  What would move onto Precogly:

  - Re-validating credentials the client echoes back. `form_valid` re-checks the
    `resource` values because "the hidden form field can be tampered with"; an SPA
    round-trips the same values over the same untrusted path, and missing the check fails
    nothing.
  - `AuthorizationForm`'s field validation, rewritten as a serializer.
  - The error and prompt paths: `error_response`, `redirect`, `handle_prompt_login`,
    `handle_prompt_create`. Dropping the last two loses OIDC `prompt` handling silently.
  - **What authenticates the consent POST.** A DRF view authenticates with a JWT, which
    proves someone signed in up to sixty minutes ago and cannot be revoked in the
    interval. [0007](0007-re-authenticating-at-consent.md) requires consent to be granted
    by a session that has *just* authenticated. The SPA would have to re-authenticate
    before the POST — rebuilding the second sign-in inside itself, and saving only the
    templates.

  So the gate is not "consent carries product logic" alone. Product logic is what makes
  the SPA attractive; the fourth item is what makes it expensive. Reopen when there is an
  answer to how the SPA proves recent authentication — a short-lived re-auth token from a
  password re-entry, or 0007's deferred bridge endpoint minting a fresh session.

  Read against django-oauth-toolkit 3.4.1. The first three items are read off the
  library; the fourth is reasoned, not built. A spike — one DRF view calling
  `create_authorization_response` — would settle it before anyone plans around it.

- **Leaving the hand-written CSS** and re-syncing when someone notices. Rejected because
  the three defects above are what "when someone notices" looks like.

## Trade-offs

- **`backend/static/css/auth.css` is a committed build artifact**, and nothing rebuilds it
  in CI. Editing a class in a template without running `npm run build:auth-css` fails
  silently in one direction: existing classes keep working and the new one does nothing.
  A CI step that rebuilds and diffs would close it.

- **The backend image has no Node**, which is why the artifact is committed rather than
  built during the image build. The alternative is Node in the backend image for two
  pages.

- **The logo is duplicated.** `backend/static/img/precogly-logo.png` is a copy of the
  frontend's, downscaled from 6.2MB to 37KB because it renders at 32px. Django serves no
  frontend assets, so there is nothing to reference instead, and the copy does not follow
  the original when it changes.

- **The consent screen became a product surface**, exactly as 0004 predicted it would once
  styled. It now shows the granting account, the scopes as a list, the redirect URI, and a
  link to revocation. Each is defensible on its own; together they are the beginning of the
  backlog 0004 warned about.
