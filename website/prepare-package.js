import fs from 'fs';

const path = '../crates/redos-wasm/pkg/package.json';

const file = JSON.parse(fs.readFileSync(path));

file.type = 'module';
file.main = file.module;
delete file.module;

fs.writeFileSync(path, JSON.stringify(file, null, 2));
