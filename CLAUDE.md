# AporiaLab Backend — Context for Claude Code

Arabic philosophy discussion platform. Single-file Express 4 API on Vercel + MongoDB Atlas + Mongoose 8.

## Layout
- `index.js` — entire API (~1860 lines after notifications). Schemas, helpers, middleware, and routes all live here.
- `vercel.json` — routes everything to `index.js`.
- `.env.example` — documents required env vars.

## Required env vars (set on Vercel)
| Var | Required | Purpose |
|---|---|---|
| `MONGODB_URI` | yes | Atlas cluster |
| `JWT_SECRET` | **yes** — server throws on startup if missing | JWT signing |
| `GOOGLE_CLIENT_ID` | optional | Google OAuth (returns 503 if empty) |
| `ADMIN_KEY` | optional | required for `/api/admin/*` (sent as `x-admin-key` header) |
| `ALLOWED_ORIGINS` | optional | extra CORS origins, CSV |
| `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET` | optional | enables avatar upload. All three must be set; otherwise `/api/users/avatar/signature` and `/api/users/avatar` return 503. Avatars are stored under the `aporialab/avatars` folder. |

## Core models
- `User` — name, email (unique), password (bcrypt), googleId, authProvider, avatar, bio, reputation, role, isFoundingMember.
- `Discussion` — title, content, category (beginner/intermediate/advanced), tags, author (denormalized), views, upvotes (string[] of userIds), commentCount, expiresAt, duration, stanceStats { pro, con, neutral }, editHistory.
- `Comment` — discussionId, content, author (denormalized), stance (pro/con/neutral), upvotes, reactions { logical, illogical, inspiring, unclear } (each = string[] of userIds), qualityScore, parentCommentId, isReply.
- `Circle` — name, description, category, members count, isPrivate, memberIds (string[]), pendingRequests[{ userId, userName, userAvatar, requestedAt, message }], createdBy { _id, name }.
- `Notification` (new) — recipient, sender (denormalized), type enum (9 values), title, message, link, metadata (Mixed), isRead. TTL 60 days. Indexes: (recipient, isRead, createdAt) and (recipient, type, createdAt).

## Helpers and conventions
- All routes return `{ success: bool, message?, ... }`. Error messages are in Arabic.
- `sanitizeString(str, maxLen)` — trim + slice + strip control chars.
- `authMiddleware` — verifies JWT and sets `req.user = { userId, email }`.
- `adminMiddleware` — chains after `authMiddleware`; checks `x-admin-key` + role === 'admin'.
- `createNotification({ recipient, sender, type, title, message, link, metadata })` — placed before `sanitizeString`. Skips self-notifications. Silent fail (logs to console, returns null). Always called *after* the primary `await save()` so it cannot block responses.
- `updateAuthorReputation(authorId, points)` — fire-and-forget reputation delta.
- Author/sender objects are denormalized snapshots of `{ _id, name, avatar, ... }` — never populated via `.populate()`.

## Notifications system (just shipped — Phase 1)
**Endpoints (all `authMiddleware`):**
- `GET /api/notifications?filter=all|unread|comment|reply|upvote|reaction|circle&page=&limit=`
- `GET /api/notifications/unread-count`
- `PATCH /api/notifications/:id/read`
- `PATCH /api/notifications/read-all`
- `DELETE /api/notifications/:id`

**Triggers:**
- `POST /api/discussions/:id/like` → `discussion_upvote` to discussion author (only when `isLiking === true`)
- `POST /api/discussions/:id/comments` → `comment` to discussion author OR `reply` to parent commenter
- `POST /api/comments/:id/upvote` → `comment_upvote` (only when `isUpvoting === true`)
- `POST /api/comments/:id/react` → `reaction_logical` / `reaction_inspiring` only (skips negative reactions, only on add)
- `POST /api/circles/:id/join` → `circle_join_request` to circle creator (private circles only, skipped for `system`-created circles)
- `POST /api/circles/:id/approve/:userId` → `circle_approved`
- `POST /api/circles/:id/reject/:userId` → `circle_rejected`

## Conventions to keep
1. **No smart quotes anywhere** — only ASCII `'` `"` `\``.
2. **Single file** — keep adding to `index.js`, don't split into modules without explicit ask.
3. **Validate before commit** — `node -c index.js` must pass.
4. **Atomic commits** with descriptive messages.
5. **Don't break existing routes** — additions only; if a route needs a behavior change, preserve the response shape.
6. **Sanitize all user input** with `sanitizeString` (or its size-aware override) before persisting.

## Git
- Default branch: `main`.
- Working branch convention used so far: `claude/<topic>`.
- PRs gated by Vercel preview deployments. Merge after preview is verified.

## Avatar upload (Cloudinary, signed flow)
**Endpoints (both `authMiddleware`):**
- `POST /api/users/avatar/signature` → returns `{ signature, timestamp, apiKey, cloudName, folder, publicId }`. Folder is fixed at `aporialab/avatars`. `publicId` is `user_<userId>_<timestamp>` so re-uploads don't overwrite.
- `PATCH /api/users/avatar` with `{ avatarUrl }` → validates that the URL is `https://res.cloudinary.com/<cloudName>/...` and contains the `/aporialab/avatars/` segment, sanitizes via `sanitizeString(url, 500)`, updates `user.avatar`, returns updated user. Passing empty string clears the avatar.

**Frontend flow:**
1. Fetch signature from backend.
2. `POST` the file to `https://api.cloudinary.com/v1_1/<cloudName>/image/upload` as multipart/form-data with `file`, `api_key`, `timestamp`, `folder`, `public_id`, `signature`.
3. Send the returned `secure_url` to `PATCH /api/users/avatar`.

## Backlog for next sessions
- **Better authentication flow** — password reset (uses `emailVerified` field already on User), email verification.
- Long-term: split `index.js`, add tests + CI, JWT in httpOnly cookies, password reset emails (needs SMTP/SendGrid or similar).
