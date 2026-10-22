# Contributing

Run `make ci` before sending changes. Tests are dependency-free on the Python side; schema validation needs Node + Ajv (`npm install --prefix tools`) and the independent cross-check needs Python `cryptography`.

Changes that affect evidence-pack fields, verification semantics or compatibility must go through a new protocol version; do not overwrite frozen material.
