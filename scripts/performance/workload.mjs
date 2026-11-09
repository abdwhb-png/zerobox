import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import readline from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

// This workload has no Pi dependency. The launcher supplies an owned fixture root.
const [root, action, python = '/usr/bin/python3'] = process.argv.slice(process.argv[1] === fileURLToPath(import.meta.url) ? 2 : 1);
const leaf = (depth) => path.join(root, ...Array.from({ length: depth - 1 }, (_, i) => 'd' + i), 'leaf.dat');
function child(file, args, options = {}) {
    const result = spawnSync(file, args, { cwd: root, encoding: 'utf8', timeout: 180000, ...options });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(file + ' exited ' + result.status + ': ' + result.stderr);
    return result.stdout;
}

if (action === 'prepare') {
    for (const depth of [1, 3, 8]) {
        fs.mkdirSync(path.dirname(leaf(depth)), { recursive: true });
        fs.writeFileSync(leaf(depth), Buffer.alloc(4096, 65));
    }
    const modules = path.join(root, 'modules');
    fs.mkdirSync(modules);
    for (let i = 0; i < 100; i++) {
        fs.writeFileSync(path.join(modules, 'module_' + i + '.mjs'), 'export default ' + i + ';\n');
        fs.writeFileSync(path.join(modules, 'module_' + i + '.py'), 'value = ' + i + '\n');
    }
    child('/usr/bin/git', ['init', '--quiet']);
    child('/usr/bin/git', ['add', '.']);
    child('/usr/bin/git', ['-c', 'user.name=ZeroBox benchmark', '-c', 'user.email=benchmark@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '--quiet', '-m', 'Synthetic benchmark fixture']);
    console.log(JSON.stringify({ prepared: true }));
} else {
    console.log(JSON.stringify({ ready: true, executable: process.execPath, node: process.version, filesystemType: fs.statfsSync(root).type }));
    for await (const line of readline.createInterface({ input: process.stdin })) {
        const request = JSON.parse(line);
        if (request.op === 'exit') break;
        const file = leaf(request.depth ?? 8);
        const fd = ['fstat', 'read_fd'].includes(request.op) ? fs.openSync(file, 'r') : undefined;
        const buffer = Buffer.alloc(4096);
        let checksum = 0;
        let details;
        let error;
        const cpuBefore = process.cpuUsage();
        const start = process.hrtime.bigint();
        try {
            for (let i = 0; i < request.n; i++) {
                switch (request.op) {
                    case 'stat': checksum += fs.statSync(file).size; break;
                    case 'fstat': checksum += fs.fstatSync(fd).size; break;
                    case 'read_fd': checksum += fs.readSync(fd, buffer, 0, buffer.length, 0); break;
                    case 'read_path': checksum += fs.readFileSync(file).length; break;
                    case 'open_close': { const opened = fs.openSync(file, 'r'); fs.closeSync(opened); checksum++; break; }
                    case 'missing': {
                        try { fs.statSync(file + '.absent'); throw new Error('Missing path unexpectedly exists'); }
                        catch (failure) { if (failure.code !== 'ENOENT') throw failure; checksum++; }
                        break;
                    }
                    case 'node_modules': {
                        const url = pathToFileURL(path.join(root, 'modules/')).href;
                        const source = 'let sum=0; for(let i=0;i<100;i++)sum+=(await import(' + JSON.stringify(url) + '+"module_"+i+".mjs")).default; console.log(sum)';
                        if (child(process.execPath, ['--input-type=module', '-e', source]).trim() !== '4950') throw new Error('Node import checksum mismatch');
                        checksum += 4950;
                        break;
                    }
                    case 'python_imports': {
                        const source = 'import sys, importlib; sys.path.insert(0, sys.argv[1]); print(sum(importlib.import_module("module_"+str(i)).value for i in range(100)))';
                        if (child(python, ['-B', '-c', source, path.join(root, 'modules')]).trim() !== '4950') throw new Error('Python import checksum mismatch');
                        checksum += 4950;
                        break;
                    }
                    case 'git': {
                        const output = child('/usr/bin/git', ['--no-optional-locks', 'diff', '--stat']);
                        if (output !== '') throw new Error('Synthetic Git fixture changed');
                        checksum++;
                        break;
                    }
                    case 'canary': {
                        try { fs.readFileSync(path.join(root, 'late-secret.pem')); details = { readable: true }; }
                        catch (failure) { details = { readable: false, code: failure.code }; }
                        checksum++;
                        break;
                    }
                    default: throw new Error('Unknown operation: ' + request.op);
                }
            }
        } catch (failure) {
            error = { message: failure.message, code: failure.code };
        } finally {
            if (fd !== undefined) fs.closeSync(fd);
        }
        const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
        const cpu = process.cpuUsage(cpuBefore);
        console.log(JSON.stringify({ ...request, elapsedMs, cpuMs: { user: cpu.user / 1000, system: cpu.system / 1000 }, checksum, ...(details ? { details } : {}), ...(error ? { error } : {}) }));
    }
}
