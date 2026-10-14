# HomeVault

Wallet-based file storage and sharing for Homeroom. Upload files to your own
vault, watch a vault-door meter fill against your 100 MB of free storage, and
choose who can open each file: only you, every member of the project, or
anyone with its public link. Files other members shared appear under
"Shared with you", ready to download or report.

## How it works

- **Sign-in** — the server verifies the platform-issued user token (an RS256
  JWT) on every request. Members of the project are read from the platform's
  member list.
- **Storage** — uploaded file bytes are kept in the app's own Postgres
  database (`file_chunks`, 1 MB rows), because the platform's file storage
  takes only images of up to 5 MB. The `files`, `file_chunks` and `reports`
  tables are `staging:private`.
- **Public links** — `/s/<token>` serves a file to anyone who has the link,
  signed in or not, always as a download (`application/octet-stream`,
  `nosniff`), so an uploaded file can never run on the app's origin.
- **Styling** — Tailwind CSS, precompiled by `npm run build` during image
  creation, in a light and a dark look that follow the viewer's Homeroom
  theme. The look is described in `CLAUDE.md` under "## Design".

## Staging demo

On staging, open the app with `?demo=1` to see a populated vault: eight
made-up files of your own (41.6 MB in all) and two files shared by made-up
members, labelled "Staging demo". Everything works on them, and they never
appear without `?demo=1`.

To change this app, ask Homeroom bot: open the app on Homeroom, tap the
Homeroom icon in the header, then **Suggest an improvement**. You can also
run Claude Code against this repo directly; start with `CLAUDE.md`.