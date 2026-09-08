# FieldVerify

Digital Companion for Colorimetric Field Testing, created as a functional SIH26231 prototype for the Narcotics Control Bureau.

> This prototype provides presumptive field-test classification and does not replace laboratory confirmatory testing.

## Stack

- React, TypeScript, Vite, React Router-compatible client shell, Lucide icons
- Node.js, Express, TypeScript, Multer, Zod
- SQLite and Prisma ORM
- Browser Canvas colour feature extraction
- Node `crypto` SHA-256 and RSA-SHA256 signatures

## Install and run

```powershell
npm install
npm install --prefix server
npm install --prefix client
$env:DATABASE_URL='file:./dev.db'
.\server\node_modules\.bin\prisma.cmd generate --schema prisma\schema.prisma
.\server\node_modules\.bin\prisma.cmd db push --schema prisma\schema.prisma
npm run seed --prefix server
npm run dev
```

Set a newly rotated `GEMINI_API_KEY=your_gemini_api_key_here` and optionally `GEMINI_MODEL=gemini-3.5-flash-lite` in `server/.env`. Never place the Gemini key in frontend code or client environment variables. For a deployed frontend, set `VITE_API_URL=https://your-api-service.onrender.com/api` at build time.

The frontend runs at http://localhost:5173 and the API at http://localhost:4000. To build both apps, run `npm run build`.

Demo credentials: `OP-1001` / `demo123`. A seeded supervisor is also available as `SUP-2001` / `demo123`.

## Authentication and RBAC

FieldVerify uses bcrypt password hashes and short-lived persisted bearer sessions. The backend creates a random session token at login, stores only its SHA-256 hash, and validates the session against the database for every protected request. `GET /api/auth/me` is the source of truth for the current user; `POST /api/auth/logout` revokes the server session and records a `LOGOUT` audit event.

Demo accounts:

| Account | Operator ID | Password | Role |
| --- | --- | --- | --- |
| Field Operator | `OP-1001` | `demo123` | `FIELD_OPERATOR` |
| Supervisor | `SUP-1001` | `super123` | `SUPERVISOR` |

Permissions are centralized in `server/src/auth.ts`. Field operators can create and analyze tests, view verification status, and see only their own test data and activity. Supervisors can see all records and activity, verify integrity, review and approve/reject records, access expanded analytics, manage verification exceptions, view the complete audit trail, and export CSV audit reports. Backend middleware returns `401` for missing or expired sessions and `403` for authenticated users without permission; hiding navigation items is only an additional frontend layer.

| Feature | Field Operator | Supervisor |
| --- | --- | --- |
| Create Test | Yes | Yes |
| Analyze Test | Yes | Yes |
| View Own Tests | Yes | Yes |
| View All Tests | No | Yes |
| Review Tests | No | Yes |
| Approve/Reject | No | Yes |
| Analytics | No | Yes |
| Verification Exceptions | No | Yes |
| Audit Reports | No | Yes |
| Audit Trail | Own | All |
| Logout | Yes | Yes |

Supervisor routes include `/supervisor/review`, `/supervisor/analytics`, `/supervisor/exceptions`, `/supervisor/audit`, and `/supervisor/export`. A field operator entering one directly receives an Access Denied view, while the corresponding API returns `403`.

To QA the boundary, log in as `OP-1001`, confirm the history contains only the three operator-owned seeded records, then request `/api/supervisor/analytics` with its bearer token and expect `403`. Log in as `SUP-1001` and confirm all four seeded records, pending review access, approval/rejection, analytics, exceptions, audit trail, and CSV export. Logout, then reuse the old token against `/api/auth/me`; it returns `401`.

## Implementation

- The guided workflow is in `client/src/App.tsx`. It creates a real database record, accepts a camera/upload image, extracts average RGB and HSV features with Canvas, sends those features to the backend, captures GPS with a demo fallback, and signs the finished record.
- Explainable classification lives in `server/src/services/classificationService.ts`. Thresholds are centralized in `server/src/classificationConfig.ts`; ambiguous signals return `INCONCLUSIVE`.
- SHA-256 hashing and canonical RSA signing live in `server/src/services/securityService.ts`. The hash is calculated from uploaded image bytes on the server, never from a frontend-generated random value.
- `GET /api/tests/:id/verify` re-hashes the stored image and verifies the RSA signature against the canonical record fields. The detail screen exposes verification and a local-only “Simulate tampering” view for demonstrations.
- `AuditEvent` records creation, capture, analysis, result, location, signing and successful verification events.

## API

`POST /api/auth/login`, `GET /api/tests`, `GET /api/tests/:id`, `GET /api/tests/:id/status`, `POST /api/tests`, `POST /api/tests/:id/image`, `POST /api/tests/:id/analyze`, `POST /api/tests/:id/location`, `POST /api/tests/:id/sign`, `GET /api/tests/:id/verify`, `POST /api/tests/:id/report`, `GET /api/reports`, `POST /api/ai/chat`, and `GET /api/dashboard/stats`.

## Gemini assistants

The authenticated backend derives the role from the session and uses separate prompts and context builders in `server/src/services/aiService.ts`. `FIELD_OPERATOR` context contains only the current user's profile, tests, activity, and submitted reports. `SUPERVISOR` context contains authorized oversight records, activity, reports, analytics, and exceptions. Conversations and messages are persisted with a user relation, so one account cannot load another account's chat history.

The floating assistant is labelled **Field Assistant** for operators and **Supervisor Copilot** for supervisors. If Gemini is unavailable or the key is missing, the API returns a safe `503` message and the core application continues working.

After deterministic colour analysis, the backend can send the captured image and algorithm features to Gemini for supporting visual assessment. The structured response is validated before use and stores nullable `aiAnalysis`, `aiConfidence`, `aiConsistency`, `aiReviewRecommended`, `aiExplanation`, `aiModel`, and `aiAnalyzedAt` fields on `TestRecord`. The deterministic result and algorithm confidence remain primary. A poor image, uncertain assessment, or mismatch recommends supervisor review without changing the official presumptive result. The existing hash and signature workflow remains unchanged.

## Reports and flags

Operators can flag their own record from its status-only detail view using `POST /api/tests/:id/report`. Reports reuse `VerificationException` and store reason, description, priority, status, resolution, and audit events. Supervisors manage them in **Reports & flags** using `OPEN`, `UNDER_REVIEW`, `RESOLVED`, or `DISMISSED`. This is a human-review workflow; neither deterministic checks nor Gemini accuse an operator of misconduct.

## Limitations and future work

This is a local demonstration. Authentication is seeded, signing keys are development keys, classification uses a small explainable colour model, and offline sync is represented by the client architecture rather than a production sync queue. A production implementation should use managed identity, device-bound key custody, validated reference-card geometry, a calibrated training set, encrypted storage, HTTPS, and a real sync/conflict strategy.

## Judge flow

Login, open Dashboard, create a New field test, upload any JPG/PNG/WebP image, inspect the reference-card and quality steps, run analysis, accept GPS or demo location, generate the hash and RSA signature, open Test Details, verify the record, then use Simulate tampering and verify again. Every seeded record is fictional demo data.
