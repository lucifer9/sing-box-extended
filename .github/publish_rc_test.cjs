const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const tag = 'rc-test';
const archives = [
  'sing-box-rc-test-linux-amd64.tar.gz',
  'sing-box-rc-test-linux-arm64.tar.gz',
  'sing-box-rc-test-macos-arm64.tar.gz',
];

module.exports = async function publish({ github, context, core, version, directory = 'dist' }) {
  if (context.eventName !== 'workflow_dispatch' || context.ref !== 'refs/heads/rc') {
    throw new Error('RC downloads may only be published by a manual build of rc');
  }
  if (!version) throw new Error('Missing RC build version');

  // Check the complete download set before changing any remote state.
  const files = (await fs.readdir(directory)).sort();
  if (files.join('\n') !== [...archives].sort().join('\n')) {
    throw new Error(`Expected exactly ${archives.length} RC CLI archives`);
  }
  const checksums = [];
  for (const name of archives) {
    const file = path.join(directory, name);
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.size === 0) throw new Error(`Invalid archive: ${name}`);
    const hash = createHash('sha256').update(await fs.readFile(file)).digest('hex');
    checksums.push(`${hash}  ${name}`);
  }
  const checksumData = Buffer.from(`${checksums.join('\n')}\n`);
  const names = [...archives, 'SHA256SUMS'];
  const repo = context.repo;
  const releases = await github.paginate(github.rest.repos.listReleases, { ...repo, per_page: 100 });
  let release = releases.find((entry) => entry.tag_name === tag);
  if (release?.immutable) throw new Error('rc-test must allow release asset and tag updates');
  if (!release) {
    // Keep the first release private until its complete set of assets is ready.
    ({ data: release } = await github.rest.repos.createRelease({
      ...repo,
      tag_name: tag,
      target_commitish: context.sha,
      name: 'RC self-test',
      draft: true,
      prerelease: true,
      make_latest: 'false',
    }));
  }
  const assets = await github.paginate(github.rest.repos.listReleaseAssets, {
    ...repo, release_id: release.id, per_page: 100,
  });
  for (const name of names) {
    // GitHub has no atomic multi-asset replacement. Upload checksums last so
    // callers can detect a mixed set while these fixed URLs are being updated.
    const data = name === 'SHA256SUMS' ? checksumData : await fs.readFile(path.join(directory, name));
    const previous = assets.find((asset) => asset.name === name);
    if (previous) await github.rest.repos.deleteReleaseAsset({ ...repo, asset_id: previous.id });
    await github.rest.repos.uploadReleaseAsset({
      ...repo,
      release_id: release.id,
      name,
      data,
      headers: { 'content-type': 'application/octet-stream', 'content-length': data.length },
    });
  }

  // Editing target_commitish alone does not move an existing tag.
  let existingTag;
  try {
    existingTag = await github.rest.git.getRef({ ...repo, ref: `tags/${tag}` });
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  if (existingTag) {
    await github.rest.git.updateRef({ ...repo, ref: `tags/${tag}`, sha: context.sha, force: true });
  } else {
    await github.rest.git.createRef({ ...repo, ref: `refs/tags/${tag}`, sha: context.sha });
  }
  const baseURL = `${context.serverUrl}/${repo.owner}/${repo.repo}`;
  const links = names.map((name) => `- [${name}](${baseURL}/releases/download/${tag}/${name})`).join('\n');
  const body = [
    'Developer self-test builds. These fixed URLs are replaced by each successful manual build.',
    '',
    `Version: \`${version}\``,
    `Commit: \`${context.sha}\``,
    `[Workflow run](${baseURL}/actions/runs/${context.runId})`,
    '',
    'Linux and macOS CLI only; arm64 is aarch64. No NaiveProxy, manager, or admin panel.',
    'No distribution signing or notarization. See BUILD_INFO.txt inside each archive.',
    'Asset replacement is not atomic; verify SHA256SUMS and retry if an update is in progress.',
    '',
    links,
  ].join('\n');
  await github.rest.repos.updateRelease({
    ...repo,
    release_id: release.id,
    tag_name: tag,
    target_commitish: context.sha,
    name: 'RC self-test',
    body,
    draft: false,
    prerelease: true,
    make_latest: 'false',
  });
  await core.summary.addHeading('RC self-test downloads').addRaw(`${body}\n`).write();
};
