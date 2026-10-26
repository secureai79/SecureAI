'use strict';

// TypeScript compiler API bridge. Reads {filePath, text} from stdin and emits
// a compact, language-neutral analysis JSON object. This is intentionally a
// conservative static analysis: AST-backed, syntax-aware, and data-flow aware
// for common local-variable/function-parameter patterns; it does not execute
// application code or claim whole-program points-to precision.
const fs = require('fs');
const cp = require('child_process');

function loadTS() {
  const path = require('path');
  const candidates = [];

  // 1. Normal Node module resolution.
  try {
    candidates.push(require.resolve('typescript'));
  } catch (_) {}

  // 2. Explicit override.
  if (process.env.TYPESCRIPT_MODULE_PATH) {
    candidates.push(process.env.TYPESCRIPT_MODULE_PATH);
  }

  // 3. NODE_PATH entries.
  if (process.env.NODE_PATH) {
    for (const root of process.env.NODE_PATH.split(path.delimiter)) {
      candidates.push(
        path.join(root, 'typescript', 'lib', 'typescript.js')
      );
    }
  }

  // 4. Project-local node_modules.
  //
  // ts_ast_bridge.js lives several directories below the repository root:
  // backend/app/scanner/languages/javascript/
  const projectRoot = path.resolve(__dirname, '../../../../..');

  candidates.push(
    path.join(projectRoot, 'node_modules', 'typescript', 'lib', 'typescript.js')
  );

  // 5. Backend-local node_modules, if present.
  candidates.push(
    path.join(__dirname, '../../../../../node_modules/typescript/lib/typescript.js')
  );

  // 6. Global npm installation.
  try {
    const npmRoot = cp.execFileSync(
      'npm',
      ['root', '-g'],
      { encoding: 'utf8' }
    ).trim();

    if (npmRoot) {
      candidates.push(
        path.join(npmRoot, 'typescript', 'lib', 'typescript.js')
      );
    }
  } catch (_) {}

  // 7. Common Linux Docker location.
  candidates.push(
    '/usr/local/lib/node_modules/typescript/lib/typescript.js'
  );

  for (const p of candidates) {
    try {
      return require(p);
    } catch (_) {}
  }

  throw new Error(
    'TypeScript compiler API is unavailable. ' +
    'Install typescript or set TYPESCRIPT_MODULE_PATH.'
  );
}
const ts = loadTS();

const AI_CONSTRUCTORS = new Map([
  ['OpenAI', 'OpenAI'], ['AsyncOpenAI', 'OpenAI'], ['Anthropic', 'Anthropic'],
  ['AsyncAnthropic', 'Anthropic'], ['GoogleGenerativeAI', 'Gemini'],
  ['GenerativeModel', 'Gemini'], ['ChatOpenAI', 'OpenAI'], ['ChatAnthropic', 'Anthropic']
]);
const AI_CHAIN_HINTS = /(^|\.)(openai|anthropic|generativeai|generativemodel|chatopenai|chatanthropic|gemini)(\.|$)/i;
const AI_METHODS = new Set(['create','complete','completion','generate','generateContent','invoke','run','chat','predict','stream','responses']);
const APPROVAL_HINT = /(require.?approval|human.?approval|needs.?approval|manual.?review|pending.?approval|confirm|authorize)/i;
const LIMIT_HINT = /(limit|max|threshold|amount|value|price|total|count)/i;

const DANGEROUS = [
  [/stripe\..*refund/i, 'FINANCIAL', 'refund'],
  [/stripe\..*charge/i, 'FINANCIAL', 'charge'],
  [/\btransfer\b/i, 'FINANCIAL', 'transfer'],
  [/\bpayout\b/i, 'FINANCIAL', 'payout'],
  [/(cursor|conn|session|db|pool|client)\..*execute/i, 'DATA', 'execute_sql'],
  [/\b(sendmail|sendEmail|sendMessage|send)\b/i, 'COMMUNICATION', 'send'],
  [/(^|\.)os\.system$/i, 'INFRASTRUCTURE', 'execute'],
  [/(^|\.)(exec|execSync|spawn|spawnSync|run|Popen|call|check_output)$/i, 'INFRASTRUCTURE', 'execute'],
  [/(kubernetes|k8s|docker|terraform|helm|ec2|ecs|eks).*deploy/i, 'INFRASTRUCTURE', 'deploy'],
  [/\.terminate(Instance|Instances)?$/i, 'INFRASTRUCTURE', 'terminate'],
  [/\.merge$/i, 'CODE', 'merge'],
  [/\bpush$/i, 'CODE', 'push']
];

function chain(node) {
  if (!node) return '';
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return `${chain(node.expression)}.${node.name.text}`;
  if (ts.isElementAccessExpression(node)) return `${chain(node.expression)}[]`;
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) return chain(node.expression);
  return '';
}
function line(sf, node) { return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1; }
function snippet(sf, node) { return sf.text.split(/\r?\n/)[line(sf,node)-1] || ''; }
function names(node) {
  const out = new Set();
  function walk(n) {
    if (ts.isIdentifier(n)) out.add(n.text);
    ts.forEachChild(n, walk);
  }
  if (node) walk(node);
  return out;
}
function exprTainted(expr, taint, aiVars, aiFunctions) {
  if (!expr) return false;
  if (ts.isIdentifier(expr)) return taint.has(expr.text);
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) return exprTainted(expr.expression, taint, aiVars, aiFunctions);
  if (ts.isParenthesizedExpression(expr) || ts.isAsExpression(expr) || ts.isNonNullExpression(expr) || ts.isTypeAssertionExpression(expr) || ts.isAwaitExpression(expr)) return exprTainted(expr.expression, taint, aiVars, aiFunctions);
  if (ts.isConditionalExpression(expr)) return exprTainted(expr.whenTrue, taint, aiVars, aiFunctions) || exprTainted(expr.whenFalse, taint, aiVars, aiFunctions);
  if (ts.isBinaryExpression(expr)) return exprTainted(expr.left, taint, aiVars, aiFunctions) || exprTainted(expr.right, taint, aiVars, aiFunctions);
  if (ts.isTemplateExpression(expr)) return expr.templateSpans.some(s => exprTainted(s.expression, taint, aiVars, aiFunctions));
  if (ts.isObjectLiteralExpression(expr)) return expr.properties.some(p => (ts.isPropertyAssignment(p) && exprTainted(p.initializer, taint, aiVars, aiFunctions)) || (ts.isShorthandPropertyAssignment(p) && exprTainted(p.name, taint, aiVars, aiFunctions)));
  if (ts.isArrayLiteralExpression(expr)) return expr.elements.some(e => exprTainted(e, taint, aiVars, aiFunctions));
  if (ts.isCallExpression(expr) || ts.isNewExpression(expr)) {
    const c = chain(expr);
    const base = c.split('.')[0];
    const last = c.split('.').pop();
    if (aiFunctions.has(base) || (aiVars.has(base) && AI_METHODS.has(last))) return true;
    return expr.arguments.some(a => exprTainted(a, taint, aiVars, aiFunctions));
  }
  return false;
}
function hasGuard(functionNode, callNode) {
  let approval = false, limit = false;
  const callNames = new Set();
  for (const arg of callNode.arguments || []) for (const n of names(arg)) callNames.add(n);
  function visit(n) {
    if (n === callNode) return;
    if (ts.isIfStatement(n)) {
      const end = n.thenStatement.getEnd();
      if (end <= callNode.getStart()) {
        const condText = n.expression.getText();
        const thenText = n.thenStatement.getText();
        if (APPROVAL_HINT.test(condText) || APPROVAL_HINT.test(thenText)) approval = true;
        const condNames = names(n.expression);
        const overlaps = [...condNames].some(x => callNames.has(x));
        if (overlaps && LIMIT_HINT.test(condText)) limit = true;
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(functionNode.body || functionNode);
  return {approval, limit};
}
function functionName(n) {
  if (n.name && ts.isIdentifier(n.name)) return n.name.text;
  return 'module';
}
function functionForCall(call, functions) {
  let best = null;
  for (const fn of functions) {
    if (call.getStart() >= fn.getStart() && call.getEnd() <= fn.getEnd()) best = fn;
  }
  return best;
}

function analyze(filePath, text) {
  function scriptKindFor(filePath) {
  const ext = require('path').extname(filePath).toLowerCase();

  // TypeScript 7 no longer exposes ts.ScriptKind.
  // createSourceFile can infer the language from the filename,
  // so return undefined and let the compiler API infer it.
  if (['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'].includes(ext)) {
    return undefined;
  }

  return undefined;
}
const sf = ts.createSourceFile(
  filePath,
  text,
  undefined,
  true
);
  if (sf.parseDiagnostics && sf.parseDiagnostics.length) {
    return {supported:false, parse_ok:false, error:'TypeScript AST parse diagnostics present', ai_providers:[], findings:[]};
  }

  const aiVars = new Map();
  const aiFunctions = new Set();
  const functions = [];
  const calls = [];

  function firstPass(n) {
    if (ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n)) functions.push(n);
    if (ts.isCallExpression(n) || ts.isNewExpression(n)) calls.push(n);
    if (ts.isVariableDeclaration(n) && n.initializer) {
      const c = chain(n.initializer);
      const last = c.split('.').pop();
      const provider = AI_CONSTRUCTORS.get(last) || (AI_CHAIN_HINTS.test(c) && AI_METHODS.has(last) ? (c.toLowerCase().includes('anthropic') ? 'Anthropic' : 'OpenAI') : null);
      if (provider && ts.isIdentifier(n.name)) aiVars.set(n.name.text, provider);
    }
    ts.forEachChild(n, firstPass);
  }
  firstPass(sf);

  for (const fn of functions) {
    let aiProducing = false;
    function scanFn(n) {
      if (ts.isCallExpression(n) || ts.isNewExpression(n)) {
        const c = chain(n), base = c.split('.')[0], last = c.split('.').pop();
        if ((aiVars.has(base) && AI_METHODS.has(last)) || AI_CHAIN_HINTS.test(c)) aiProducing = true;
      }
      ts.forEachChild(n, scanFn);
    }
    if (fn.body) scanFn(fn.body);
    if (aiProducing && fn.name && ts.isIdentifier(fn.name)) aiFunctions.add(fn.name.text);
  }

  const providers = [...new Set(aiVars.values())];
  const taintByFunction = new Map();
  for (const fn of functions) taintByFunction.set(fn, new Set());
  taintByFunction.set(sf, new Set());

  // Fixed-point local taint: AI return -> variable -> member/object/derived
  // expression, plus tainted actual argument -> local formal parameter.
  for (let round=0; round<8; round++) {
    let changed = false;
    for (const fn of [sf, ...functions]) {
      const taint = taintByFunction.get(fn);
      function walk(n) {
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
          if (exprTainted(n.initializer, taint, new Set(aiVars.keys()), aiFunctions) && !taint.has(n.name.text)) { taint.add(n.name.text); changed=true; }
        }
        if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(n.left)) {
          if (exprTainted(n.right, taint, new Set(aiVars.keys()), aiFunctions) && !taint.has(n.left.text)) { taint.add(n.left.text); changed=true; }
        }
        ts.forEachChild(n, walk);
      }
      if (fn.body) walk(fn.body); else if (fn === sf) walk(sf);
    }
    // Seed formal parameters from calls to local functions.
    for (const call of calls) {
      const callee = chain(call.expression).split('.')[0];
      const targetFn = functions.find(fn => fn.name && ts.isIdentifier(fn.name) && fn.name.text === callee);
      if (!targetFn || !targetFn.parameters) continue;
      const caller = functionForCall(call, functions) || sf;
      const callerTaint = taintByFunction.get(caller);
      const targetTaint = taintByFunction.get(targetFn);
      targetFn.parameters.forEach((p,i) => {
        if (p.name && ts.isIdentifier(p.name) && call.arguments[i] && exprTainted(call.arguments[i], callerTaint, new Set(aiVars.keys()), aiFunctions) && !targetTaint.has(p.name.text)) { targetTaint.add(p.name.text); changed=true; }
      });
    }
    if (!changed) break;
  }

  const findings = [];
  const seen = new Set();
  for (const call of calls) {
    const c = chain(call.expression);
    if (!c) continue;
    let rule = null;
    for (const [re, category, operation] of DANGEROUS) { if (re.test(c)) { rule=[category,operation]; break; } }
    if (!rule) continue;
    const fn = functionForCall(call, functions) || sf;
    const taint = taintByFunction.get(fn) || new Set();
    const aiControlled = call.arguments.some(a => exprTainted(a, taint, new Set(aiVars.keys()), aiFunctions));
    // Direct AI call used as an argument is also a traced source.
    const directAI = call.arguments.some(a => {
      if (!(ts.isCallExpression(a) || ts.isNewExpression(a))) return false;
      const ac = chain(a), base=ac.split('.')[0], last=ac.split('.').pop();
      return (aiVars.has(base) && AI_METHODS.has(last)) || AI_CHAIN_HINTS.test(ac);
    });
    const controlled = aiControlled || directAI;
    const guard = hasGuard(fn, call);
    const key = `${rule[1]}:${line(sf,call)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const capChain = [];
    if (controlled) capChain.push('AI-generated value');
    capChain.push(rule[1].replace('_',' '));
    findings.push({
      category: rule[0], operation: rule[1], chain:c, line:line(sf,call),
      ai_controlled: controlled, control_confidence: controlled ? 0.92 : 0.55,
      approval_detected:guard.approval, limit_detected:guard.limit,
      capability_chain:capChain, snippet_line:snippet(sf,call),
      function_name:functionName(fn),
      ai_provider: providers[0] || null
    });
  }
  return {supported:true, parse_ok:true, ai_providers:providers, findings};
}

let input = '';
process.stdin.setEncoding('utf8');

function processRequest(line) {
  if (!line.trim()) return;

  try {
    const obj = JSON.parse(line);
    const result = analyze(obj.filePath, obj.text);
    process.stdout.write(JSON.stringify(result) + '\n');
  } catch (e) {
    process.stdout.write(JSON.stringify({
      error: String(e && e.stack || e)
    }) + '\n');
  }
}

process.stdin.on('data', chunk => {
  input += chunk;

  let newlineIndex;
  while ((newlineIndex = input.indexOf('\n')) !== -1) {
    const line = input.slice(0, newlineIndex);
    input = input.slice(newlineIndex + 1);
    processRequest(line);
  }
});

process.stdin.on('end', () => {
  if (input.trim()) {
    processRequest(input);
  }
});
