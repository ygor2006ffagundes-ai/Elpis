# Elpis — web app

Where Hope Meets Opportunity. This folder is the Elpis prototype as a web app you can put on GitHub Pages and add to an iPhone Home Screen.

## Put it online with GitHub Pages (about 5 minutes, free)

1. Sign in at github.com and create a new **public** repository, for example `elpis`.
2. On the empty repository page, click **uploading an existing file**.
3. Drag **everything inside this folder** (index.html, app.js, app.css, manifest.webmanifest, sw.js, the `icons` folder and this README) into the page. Don't drag the folder itself. Click **Commit changes**.
4. Open **Settings → Pages**. Under "Build and deployment", set **Source: Deploy from a branch**, **Branch: main**, folder **/ (root)**, and click **Save**.
5. After 1–2 minutes the page shows your link: `https://YOUR-USERNAME.github.io/elpis/`.

## Install it on your iPhone

1. Open the link in **Safari**.
2. Tap **Share** (the square with an arrow) → **Add to Home Screen** → **Add**.
3. Open **Elpis** from your Home Screen. It runs full screen, like an app.

## Good to know

- Accounts, posts and uploads are saved **on each device** (in the browser). They don't sync between phones yet; that needs a server.
- After the first visit the app also opens offline.
- To update: upload the new files to the same repository (replace the old ones). The app picks up the new version the next time it's opened online.
