const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const publish = require('./publish_rc_test.cjs');

const archiveNames = ['linux-amd64', 'linux-arm64', 'macos-arm64']
  .map((target) => `sing-box-rc-test-${target}.tar.gz`);

async function fixture(t, { existing = false, uploadFailure = false, refStatus, immutable = false } = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'rc-publish-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  for (const name of archiveNames) await fs.writeFile(path.join(directory, name), `binary for ${name}`);
  const calls = [];
  const method = (name, implementation) => async (args) => {
    calls.push({ name, args });
    return { data: await implementation(args) };
  };
  const release = { id: 7, tag_name: 'rc-test', immutable };
  const repos = {
    listReleases: method('listReleases', () => existing ? [release] : []),
    createRelease: method('createRelease', () => release),
    listReleaseAssets: method('listReleaseAssets', () => existing ? [
      ...archiveNames.map((name, id) => ({ name, id })),
      { name: 'sing-box-rc-test-macos-amd64.tar.gz', id: 3 },
      { name: 'SHA256SUMS', id: 4 },
      { name: 'unrelated.txt', id: 99 },
    ] : []),
    deleteReleaseAsset: method('deleteReleaseAsset', () => ({})),
    uploadReleaseAsset: method('uploadReleaseAsset', ({ name }) => {
      if (uploadFailure && name === archiveNames[1]) throw new Error('upload failed');
      return {};
    }),
    updateRelease: method('updateRelease', () => ({})),
  };
  const git = {
    getRef: method('getRef', () => {
      if (refStatus || !existing) throw Object.assign(new Error('ref lookup failed'), { status: refStatus || 404 });
      return { object: { sha: 'old-commit' } };
    }),
    createRef: method('createRef', () => ({})),
    updateRef: method('updateRef', () => ({})),
  };
  const summary = {
    text: '',
    written: false,
    addHeading() { return this; },
    addRaw(text) { this.text += text; return this; },
    async write() { this.written = true; },
  };
  const options = {
    directory,
    version: '1.14.0-rc-test.1.1-123456789abc',
    github: { rest: { repos, git }, paginate: async (call, args) => (await call(args)).data },
    context: {
      repo: { owner: 'example', repo: 'sing-box' },
      eventName: 'workflow_dispatch',
      ref: 'refs/heads/rc',
      sha: '123456789abcdef0123456789abcdef0123456789',
      serverUrl: 'https://github.com',
      runId: 123,
    },
    core: { summary },
  };
  return { options, calls, summary };
}

test('first publication uploads all downloads before publishing a non-latest pre-release', async (t) => {
  const { options, calls, summary } = await fixture(t);
  await publish(options);
  const created = calls.find((call) => call.name === 'createRelease').args;
  assert.equal(created.draft, true);
  assert.equal(created.target_commitish, options.context.sha);
  const uploads = calls.filter((call) => call.name === 'uploadReleaseAsset');
  assert.deepEqual(uploads.map((call) => call.args.name), [...archiveNames, 'SHA256SUMS']);
  const checksums = uploads.at(-1).args.data.toString();
  for (const { args } of uploads.slice(0, -1)) {
    const hash = createHash('sha256').update(args.data).digest('hex');
    assert.ok(checksums.includes(`${hash}  ${args.name}\n`));
  }
  const tag = calls.find((call) => call.name === 'createRef').args;
  assert.equal(tag.ref, 'refs/tags/rc-test');
  assert.equal(tag.sha, options.context.sha);
  const update = calls.at(-1);
  assert.equal(update.name, 'updateRelease');
  assert.equal(update.args.draft, false);
  assert.equal(update.args.prerelease, true);
  assert.equal(update.args.make_latest, 'false');
  assert.ok(update.args.body.includes(options.context.sha));
  assert.equal(summary.written, true);
  assert.ok(summary.text.includes('https://github.com/example/sing-box/releases/download/rc-test/'));
});

test('replaces current RC assets, preserves retired assets, and moves the tag after uploads succeed', async (t) => {
  const { options, calls } = await fixture(t, { existing: true });
  await publish(options);
  assert.equal(calls.some((call) => call.name === 'createRelease' || call.name === 'createRef'), false);
  assert.deepEqual(calls.filter((call) => call.name === 'deleteReleaseAsset').map((call) => call.args.asset_id), [0, 1, 2, 4]);
  const movedAt = calls.findIndex((call) => call.name === 'updateRef');
  assert.ok(movedAt > calls.findLastIndex((call) => call.name === 'uploadReleaseAsset'));
  assert.equal(calls[movedAt].args.sha, options.context.sha);
  assert.equal(calls[movedAt].args.force, true);
});

test('rejects incomplete, empty, or unexpected downloads before contacting GitHub', async (t) => {
  for (const invalid of ['missing', 'empty', 'extra', 'retired-platform']) {
    await t.test(invalid, async (t) => {
      const { options, calls } = await fixture(t);
      const first = path.join(options.directory, archiveNames[0]);
      if (invalid === 'missing') await fs.unlink(first);
      if (invalid === 'empty') await fs.writeFile(first, '');
      if (invalid === 'extra') await fs.writeFile(path.join(options.directory, 'unexpected.apk'), 'apk');
      if (invalid === 'retired-platform') {
        await fs.writeFile(path.join(options.directory, 'sing-box-rc-test-macos-amd64.tar.gz'), 'retired binary');
      }
      await assert.rejects(publish(options), /archive/);
      assert.deepEqual(calls, []);
    });
  }
});

test('rejects automatic or non-RC publication before contacting GitHub', async (t) => {
  for (const change of [{ eventName: 'push' }, { ref: 'refs/heads/main' }]) {
    const { options, calls } = await fixture(t);
    Object.assign(options.context, change);
    await assert.rejects(publish(options), /manual build of rc/);
    assert.deepEqual(calls, []);
  }
});

test('failed upload cannot move the tag or report successful publication', async (t) => {
  const { options, calls, summary } = await fixture(t, { existing: true, uploadFailure: true });
  await assert.rejects(publish(options), /upload failed/);
  assert.equal(calls.some((call) => ['createRef', 'updateRef', 'updateRelease'].includes(call.name)), false);
  assert.equal(summary.written, false);
});

test('does not treat permission failures as missing tags', async (t) => {
  const { options, calls, summary } = await fixture(t, { existing: true, refStatus: 403 });
  await assert.rejects(publish(options), /ref lookup failed/);
  assert.equal(calls.some((call) => ['createRef', 'updateRef', 'updateRelease'].includes(call.name)), false);
  assert.equal(summary.written, false);
});

test('rejects an immutable release without mutation', async (t) => {
  const { options, calls } = await fixture(t, { existing: true, immutable: true });
  await assert.rejects(publish(options), /must allow/);
  assert.deepEqual(calls.map((call) => call.name), ['listReleases']);
});
