// Mock Strategy class
class Strategy {
  constructor(options, verify) {
    this.options = options;
    this.verify = verify;
    this.name = options.name || 'openidconnect';
  }

  authenticate(_req, _options) {
    // Mock authenticate method
    return this;
  }
}

// Mock VerifyFunction type (for TypeScript, but exported as undefined in JS)
const VerifyFunction = undefined;

// Mock StrategyOptions type (for TypeScript, but exported as undefined in JS)
const StrategyOptions = undefined;

// Mock AuthenticateOptions type (for TypeScript, but exported as undefined in JS)
const AuthenticateOptions = undefined;

module.exports = {
  Strategy,
  VerifyFunction,
  StrategyOptions,
  AuthenticateOptions,
};