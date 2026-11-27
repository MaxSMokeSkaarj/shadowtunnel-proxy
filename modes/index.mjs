import onionMode from './onion.mjs';
import ptpMode from './ptp.mjs';

const modeRegistry = new Map();
const commandToMode = new Map();

/**
 * Register a circuit routing mode plugin (`onion`, `ptp`, or custom extensions).
 */
export function registerMode(modePlugin) {
  if (!modePlugin?.name || typeof modePlugin.openCircuit !== 'function') {
    throw new TypeError('Mode plugin must define "name" and "openCircuit(options)"');
  }
  modeRegistry.set(modePlugin.name, modePlugin);
  if (Array.isArray(modePlugin.relayCommands)) {
    for (const cmd of modePlugin.relayCommands) {
      commandToMode.set(cmd, modePlugin);
    }
  }
  return modePlugin;
}

export function getMode(name) {
  const mode = modeRegistry.get(name);
  if (!mode) {
    throw new TypeError(`Unknown proxy mode "${name}" (registered: ${listModes().join(', ')})`);
  }
  return mode;
}

export function getModeByCommand(cmd) {
  return commandToMode.get(cmd) || null;
}

export function listModes() {
  return Array.from(modeRegistry.keys());
}

export function resolveRelayCommands(modeSpec = 'both') {
  if (modeSpec === 'both' || modeSpec === 'all') {
    return Array.from(commandToMode.keys());
  }
  const plugin = getMode(modeSpec);
  return plugin.relayCommands || [];
}

export function openProxyCircuit(options) {
  const plugin = getMode(options.mode || 'onion');
  return plugin.openCircuit(options);
}

// Register built-in modes
registerMode(onionMode);
registerMode(ptpMode);
