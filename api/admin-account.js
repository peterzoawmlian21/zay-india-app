// Vercel serverless function: admin-only account actions that a web page is not allowed to do itself.
//   POST /api/admin-account   { "action": "reset-password" | "delete", "uid": "<customer uid>" }
//   Header: Authorization: Bearer <Firebase ID token of the signed-in admin>
//
// Needs one environment variable in Vercel (Project → Settings → Environment Variables):
//   FIREBASE_SERVICE_ACCOUNT = the full JSON of a Firebase service-account key.
// The key is a secret: it must never be committed to the repo or sent to the browser.
const crypto = require('crypto');
const admin = require('firebase-admin');

const DATABASE_URL = 'https://zayindia-default-rtdb.asia-southeast1.firebasedatabase.app';

function getApp() {
  if (admin.apps.length) return admin.app();
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!raw) return null;
  return admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)), databaseURL: DATABASE_URL });
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// No look-alike characters (0/O, 1/l/I) so it is easy to read out over WhatsApp.
function generateTemporaryPassword(length = 12) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from({ length }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
}

async function requireAdmin(req) {
  const match = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!match) throw new HttpError(401, 'Sign in first.');
  let decoded;
  try {
    // checkRevoked: a signed-out or reset session can't be reused.
    decoded = await admin.auth().verifyIdToken(match[1], true);
  } catch {
    throw new HttpError(401, 'Your session has expired. Sign in again.');
  }
  const isAdmin = (await admin.database().ref(`admins/${decoded.uid}`).once('value')).val() === true;
  if (!isAdmin) throw new HttpError(403, 'Admin access required.');
  return decoded.uid;
}

async function getCustomerUid(body) {
  const uid = body && body.uid;
  if (typeof uid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(uid)) throw new HttpError(400, 'Missing customer id.');
  if ((await admin.database().ref(`admins/${uid}`).once('value')).val() === true) {
    throw new HttpError(403, 'Admin accounts cannot be changed here.');
  }
  return uid;
}

async function resetPassword(uid) {
  let user;
  try {
    user = await admin.auth().getUser(uid);
  } catch (error) {
    if (error.code === 'auth/user-not-found') throw new HttpError(404, 'This customer has no login account.');
    throw error;
  }
  // Google-login customers have no password; giving them one would add a second way into the account.
  if (!user.providerData.some(provider => provider.providerId === 'password')) {
    throw new HttpError(409, 'This customer signs in with Google, so there is no password to reset. Ask them to use "Continue with Google".');
  }
  const temporaryPassword = generateTemporaryPassword();
  await admin.auth().updateUser(uid, { password: temporaryPassword });
  await admin.auth().revokeRefreshTokens(uid); // signs them out of other devices
  await admin.database().ref(`users/${uid}/passwordResetRequired`).set(true);
  // Returned once to the admin to send on WhatsApp; never stored.
  return { temporaryPassword };
}

async function deleteCustomer(uid) {
  try {
    await admin.auth().deleteUser(uid);
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
  }
  const db = admin.database();
  const phone = (await db.ref(`users/${uid}/phone`).once('value')).val();
  const updates = { [`users/${uid}`]: null };
  if (phone && (await db.ref(`phones/${phone}`).once('value')).val() === uid) updates[`phones/${phone}`] = null;
  await db.ref().update(updates);
  return { deleted: true };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Use POST.' });
  }
  try {
    if (!getApp()) throw new HttpError(503, 'Password reset is not set up yet: FIREBASE_SERVICE_ACCOUNT is missing in Vercel.');
    await requireAdmin(req);
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const uid = await getCustomerUid(body);
    if (body.action === 'reset-password') return res.status(200).json(await resetPassword(uid));
    if (body.action === 'delete') return res.status(200).json(await deleteCustomer(uid));
    throw new HttpError(400, 'Unknown action.');
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    if (status === 500) console.error('admin-account failed:', error && error.message);
    return res.status(status).json({ error: status === 500 ? 'Something went wrong on the server. Please try again.' : error.message });
  }
};
