#!/usr/bin/env node
/**
 * COAX CLI entry point — argv in, exit code out.
 *
 * WHY it is this thin: the commands do the work (`commands/*.ts`), the flag
 * table validates the input (`args.ts`), and the exit-code contract lives in
 * `exit-codes.ts`. All this file owns is dispatch and the error boundary, so
 * `run()` can be called from a test with a fake `Io` and asserted on its return
 * value — the CLI's whole contract is that number.
 *
 * The responsible-use gate is NOT here: it belongs to whichever command touches
 * a target, so no future command can accidentally route around it.
 *
 * Set COAX_DEBUG=1 to see the stack behind an unexpected failure; by default a
 * user gets one line, because a stack trace is not an error message.
 */
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { CliError, parseArgs, renderHelp } from './args.js';
import { showBanner, VERSION } from './banner.js';
import { runDemoCommand } from './commands/demo.js';
import { runListCommand } from './commands/list.js';
import { runScanCommand } from './commands/scan.js';
import { EXIT_ERROR, EXIT_OK } from './exit-codes.js';
import { createConsoleIo } from './io.js';
import type { Io } from './io.js';



/** Dispatch one argv tail. Never exits the process; returns the exit code. */
export async function run(argv: readonly string[], provided?: Io): Promise<number> {
  let io = provided ?? createConsoleIo();
  try {
    const parsed = parseArgs(argv);
    // The stream's styling depends on a flag the parser has only just read, so
    // a caller-supplied IO (tests, embedders) is left exactly as it was and only
    // the console one is rebuilt.
    if (provided === undefined) {
      io = createConsoleIo(
        parsed.globals.color !== undefined ? { color: parsed.globals.color } : {},
      );
    }
    switch (parsed.command) {
      case 'version':
        io.out(VERSION);
        return EXIT_OK;
      case 'help':
        showBanner(io, parsed.globals);
        io.out(renderHelp(parsed.topic));
        return EXIT_OK;
      case 'demo':
        return await runDemoCommand(io);
      case 'list':
        return runListCommand(parsed.args, parsed.kind, io);
      case 'scan':
        return await runScanCommand(parsed.args, parsed.globals, io);
    }
  } catch (err) {
    // A CliError is an answer ("that flag does not exist"); anything else is a
    // failure, and keeps its stack so a real bug is still debuggable.
    if (err instanceof CliError) {
      io.err(`${io.style.red('coax:')} ${err.message}`);
      io.err('Run "coax --help" for usage.');
      return err.exitCode;
    }
    if (err instanceof Error) {
      io.err(`${io.style.red('coax:')} ${err.message}`);
      if (err.stack !== undefined && process.env.COAX_DEBUG) io.err(err.stack);
      return EXIT_ERROR;
    }
    throw err;
  }
}

/** Top-level boundary: a usage error is a message, anything else is a stack. */
async function main(): Promise<number> {
  try {
    return await run(process.argv.slice(2));
  } catch (err) {
    // `run` already handles every Error; this is the non-Error throw backstop.
    console.error(err);
    return EXIT_ERROR;
  }
}

/** True when this module IS the process entry point, not an import. */
function isEntryPoint(): boolean {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(argv1);
  } catch {
    return false;
  }
}

// Importing this module (tests, embedding) must not exit anything.
if (isEntryPoint()) {
  void main().then(
    (code) => process.exit(code),
    (err: unknown) => {
      console.error(err);
      process.exit(EXIT_ERROR);
    },
  );
}
