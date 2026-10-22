/* Validate real and deliberately invalid manifests with Ajv (no hand-rolled subset).
   Usage: AJV_PATH=/tmp/ajv/node_modules/ajv/dist/2020 node tools/validate_schema.js */
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const fix = path.join(root, 'docs', 'fixtures', 'evidence-pack-v0');
const schemas = {
  'agentbridge-evidence/0.1': JSON.parse(fs.readFileSync(path.join(root, 'docs', 'evidence-pack-v0.1.schema.json'))),
  'agentbridge-evidence/0.2': JSON.parse(fs.readFileSync(path.join(root, 'docs', 'evidence-pack-v0.2.schema.json'))),
};
function requireFirst(paths, label) {
  for (const p of paths) {
    try { return require(p); } catch (err) { /* try next */ }
  }
  throw new Error(label + ' not found; run: npm install --prefix tools');
}
const Ajv2020 = requireFirst([
  process.env.AJV_PATH,
  path.join(root, 'tools', 'node_modules', 'ajv', 'dist', '2020'),
  '/tmp/ajv/node_modules/ajv/dist/2020',
].filter(Boolean), 'ajv');
const addFormats = requireFirst([
  process.env.AJV_FORMATS_PATH,
  path.join(root, 'tools', 'node_modules', 'ajv-formats'),
  '/tmp/ajv/node_modules/ajv-formats',
].filter(Boolean), 'ajv-formats');
const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validators = Object.fromEntries(Object.entries(schemas).map(([v, s]) => [v, ajv.compile(s)]));

let valid = 0;
const manifests = [];
for (const name of fs.readdirSync(fix)) {
  const p = path.join(fix, name);
  if (!fs.statSync(p).isDirectory() || name === 'trust' || name === 'schema-invalid') continue;
  manifests.push({ label: 'v01/' + name, manifest: JSON.parse(fs.readFileSync(path.join(p, 'manifest.json'))) });
}
const v2root = path.join(root, 'docs', 'fixtures', 'evidence-pack-v0.2');
if (fs.existsSync(v2root)) {
  for (const name of fs.readdirSync(v2root)) {
    const p = path.join(v2root, name);
    if (!fs.statSync(p).isDirectory() || name === 'trust') continue;
    if (fs.existsSync(path.join(p, 'manifest.json'))) {
      manifests.push({ label: 'v02/' + name, manifest: JSON.parse(fs.readFileSync(path.join(p, 'manifest.json'))) });
    }
  }
}
let packs = 0;
for (const { label, manifest } of manifests) {
  const validator = validators[manifest.pack_version];
  if (!validator) { console.log('UNKNOWN VERSION ' + label + ' ' + manifest.pack_version); continue; }
  packs += 1;
  if (validator(manifest)) {
    valid += 1;
    console.log('VALID   ' + label);
  } else {
    console.log('UNEXPECTED INVALID ' + label + ' ' + JSON.stringify(validator.errors));
  }
}
const validate = validators['agentbridge-evidence/0.1'];

const expectations = {
  'missing-required': 'required',
  'wrong-type': 'type',
  'bad-enum': 'const',
  'bad-decision': 'enum',
  'bad-time': 'format',
  'extra-field': 'additionalProperties',
};
let invalid = 0;
for (const [name, keyword] of Object.entries(expectations)) {
  const manifest = JSON.parse(fs.readFileSync(path.join(fix, 'schema-invalid', name + '.json')));
  const ok = validate(manifest);
  const rejected = !ok;
  const keywordHit = rejected && validate.errors.some((e) => e.keyword === keyword);
  if (rejected && keywordHit) {
    invalid += 1;
    console.log('REJECTED ' + name + ' (' + keyword + ')');
  } else {
    console.log('MISSED   ' + name + ' expected ' + keyword + ' errors=' + JSON.stringify(validate.errors));
  }
}
console.log(`\nvalid=${valid}/${packs} invalid=${invalid}/${Object.keys(expectations).length}`);
process.exit(valid === packs && invalid === Object.keys(expectations).length ? 0 : 1);
