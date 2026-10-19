// Upload files as an artifact from outside an action, so that a hung step
// can still report what it saw. Needs ACTIONS_RUNTIME_TOKEN and
// ACTIONS_RESULTS_URL in the environment.
//
// Usage: node upload.js NAME ROOT FILE...

const { DefaultArtifactClient } = require('@actions/artifact');

const [name, root, ...files] = process.argv.slice(2);

new DefaultArtifactClient()
  .uploadArtifact(name, files, root, { retentionDays: 7 })
  .then((result) => console.log(`uploaded ${name}: id=${result.id} size=${result.size}`))
  .catch((err) => {
    console.error(`upload of ${name} failed: ${err}`);
    process.exit(1);
  });
