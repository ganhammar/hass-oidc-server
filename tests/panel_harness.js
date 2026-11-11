// Runs a test against the login panel's script, without a browser.
//
// The panel is evaluated with just enough of a browser for its classes to be
// defined. The test, the body of an async function read from stdin, then runs
// in the same context, so the panel's top-level names are in scope, and what
// it returns is printed as JSON. Nothing is rendered: tests reach the panel's
// logic and its methods that do not touch the page.
'use strict';

const fs = require('node:fs');
const vm = require('node:vm');

const [panelPath] = process.argv.slice(2);
const test = fs.readFileSync(0, 'utf8');

const context = vm.createContext({
  HTMLElement: class {},
  customElements: { define() {} },
  Intl,
  console,
});
vm.runInContext(fs.readFileSync(panelPath, 'utf8'), context, { filename: panelPath });

vm.runInContext(`(async () => {\n${test}\n})`, context)().then(
  (result) => process.stdout.write(JSON.stringify(result === undefined ? null : result)),
  (error) => {
    console.error(error);
    process.exit(1);
  }
);
