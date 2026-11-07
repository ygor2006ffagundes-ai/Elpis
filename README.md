# Elpis — web app

Where Hope Meets Opportunity. Elpis runs as a web app on GitHub Pages and can be added to an iPhone Home Screen. Accounts, profiles, posts, likes and uploads are stored in Supabase, protected by row-level security.

## Is it safe that this repository is public?

Yes. The only Supabase key in this code is the **publishable** key, which is meant to be public. What a signed-in student can read or change is decided by the security rules in the database (see `supabase-setup.sql`), not by this code:

- Private info (email, phone, birth date, residency, financial info, plan, settings) is readable only by its owner.
- Posts from students under 18, or with "Private account" on, are visible only to their author.
- "My college" posts are visible only to students at the same school.
- Each student can upload, change or delete only their own files, posts and likes.
- Visitors who aren't signed in can't read anything.

Never put the **secret key** (`sb_secret_…`), the **service_role** key or the database password in this repository.

## Update the site

Upload every file in this folder to the repository (replace the old ones) and commit. The app picks up the new version the next time it's opened online.

## Install on iPhone

Open the site in Safari → Share → Add to Home Screen → Add.
