const jwtSecret = process.env.JWT_SECRET;

if (typeof jwtSecret !== 'string' || Buffer.byteLength(jwtSecret) < 32) {
  throw new Error('JWT_SECRET must be set to at least 32 characters');
}

module.exports = jwtSecret;
