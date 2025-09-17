import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (!process.env.NODE_CONFIG_DIR) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const configDir = path.resolve(__dirname, '../../config');
  process.env.NODE_CONFIG_DIR = configDir;
}

const configModule = await import('config');
const config = configModule.default ?? configModule;

export default config;
