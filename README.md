# BeforeEmpty manual iOS build

This separate build repository contains generic CI tools and an authenticated,
encrypted source-only bundle. It grants no open-source license to BeforeEmpty.
App code, calculations, design, icon, fonts, translations and iOS project files
are preserved in the encrypted bundle. Original Git history is not included.
No certificates, private keys, passwords, profiles, device identifiers or actual
household records are in that bundle or the repository.

The original `baewumnote-studio/beforeempty-ios` repository remains private.
This repository must initially be private and may become public only after the
owner approves the exact reviewed files and secret destinations. While private,
the workflow is blocked. Only manually dispatched runs on this repository's
`main` branch can use the `beforeempty-store` environment. Configure that
environment to allow deployment from `main` only. Do not enable PR/push triggers.

The source key, existing distribution P12/password, app-specific App Store
profile, Apple API identity/private key and private-backup token belong only in
encrypted environment secrets. The backup token must be a new fine-grained
token restricted to the original private repository's Contents read/write
permission, with a short expiry. Do not reuse a broad existing account token.
This permission can also write source in that private repository; limit and
expire it carefully. These tools only create private draft releases and assets.

Linux verifies source preservation, signing guards, the real profile CMS,
existing P12/key/expiry, analysis and app tests before starting the standard
`macos-26` runner. Flutter 3.47.5 is pinned to its verified commit. Xcode 26.6
matches the existing successful device build. All action dependencies are pinned
to commits; Python dependencies have pinned versions and distribution hashes.

Every Mac run performs `flutter build ios --release --no-codesign`. With
`upload_app: false`, it stops after compilation. With `upload_app: true`, it
then signs for App Store distribution, checks the actual exported IPA and
original archive, backs both up encrypted in a draft release of the original
PRIVATE repository, validates with Apple and uploads directly to the existing
BeforeEmpty app. A used build number is rejected before rebuilding. No new
Apple app, duplicate Bundle ID or review submission is created.

No signed IPA, archive or diagnostic log is published as a public artifact or
public release. Private diagnostic backups are encrypted too. Public output
contains only generic stage results. Build/backup/upload failures are distinct;
Apple processing and actual iPhone QA still need separate confirmation.

App Store review submission requires a separate final approval.
