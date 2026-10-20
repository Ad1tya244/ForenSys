/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  experimental: {
    // Turbopack's dev-mode persistent disk cache became stable and ON BY DEFAULT as of Next.js 16.1
    // (confirmed in node_modules/next/dist/server/config-shared.js: turbopackFileSystemCacheForDev: true).
    // It writes a continuously-rewritten key-value database (hundreds of small .sst/.meta files) into
    // .next/dev/cache/turbopack/. Inside a cloud-synced folder (iCloud Drive's "Desktop & Documents Folders",
    // Dropbox, OneDrive, ...) that write pattern races the sync client, which duplicates files mid-write as
    // "name 2.ext" - Turbopack's loader then fails to parse that as a cache-entry number and throws
    // "Failed to open database: invalid digit found in string". This didn't happen before 16.1 because the
    // feature (and its on-disk database) didn't exist yet - nothing about iCloud changed, Turbopack started
    // doing much more disk I/O than it used to. Disabling just this flag reverts to the pre-16.1 in-memory-only
    // dev cache: same Turbopack bundler/speed within a running session, no persistent on-disk database for a
    // sync client to corrupt. Project location and iCloud settings are untouched.
    turbopackFileSystemCacheForDev: false,
  },
}

export default nextConfig
