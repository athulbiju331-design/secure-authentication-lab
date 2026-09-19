# Authentication Security Note

## Project
Secure Authentication Web Application — local Flask demonstration.

## Controls
- Passwords are stored as secure hashes, not plaintext.
- Registration and login are validated server-side.
- Failed login responses use a generic message.
- Five failed attempts within 60 seconds from an IP trigger a temporary rate limit.
- Sessions use HttpOnly and SameSite=Lax cookies and a 30-minute lifetime.
- Secure cookies are enabled for production HTTPS; local HTTP testing keeps the Secure flag off.
- Logout is a CSRF-protected POST that clears the session.
- State-changing forms use per-session CSRF tokens.
- User lookup uses parameterized SQL.
- Authentication security events are logged locally.

## Scope
Testing is limited to the local authorized application.
