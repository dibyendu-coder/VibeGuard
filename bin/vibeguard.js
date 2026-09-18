#!/usr/bin/env node

import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

// Use tsx loader or node module runner to execute src/cli.ts directly when in dev, or dist/cli.js in build
import '../dist/cli.js';
