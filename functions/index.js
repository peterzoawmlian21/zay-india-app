const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2');
const admin = require('firebase-admin');
const crypto = require('crypto');

admin.initializeApp();
// Same region as the Realtime Database; index.html calls functions in this region.
setGlobalOptions({ region: 'asia-southeast1', maxInstances: 5 });

// Only accounts listed under /admins/{uid} = true (set by hand in the Firebase console) may call these.
async function assertAdmin(request) {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError('unauthenticated', 'Sign in first.');
  const isAdmin = (await admin.database().ref(`admins/${uid}`).once('value')).val() === true;
  if (!isAdmin) throw new HttpsError('permission-denied', 'Admin access required.');
}

async function getCustomerUid(request) {
  const uid = request.data?.uid;
  if (typeof uid !== 'string' || !uid) throw new HttpsError('invalid-argument', 'Missing customer id.');
  if ((await admin.database().ref(`admins/${uid}`).once('value')).val() === true) {
    throw new HttpsError('permission-denied', 'Admin accounts cannot be changed here.');
  }
  return uid;
}

function generateTemporaryPassword(length = 12) {
  // No look-alike characters (0/O, 1/l/I) so it is easy to read out over WhatsApp.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from({ length }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
}

exports.resetCustomerPassword = onCall(async (request) => {
  await assertAdmin(request);
  const uid = await getCustomerUid(request);
  const temporaryPassword = generateTemporaryPassword();
  try {
    await admin.auth().updateUser(uid, { password: temporaryPassword });
  } catch (error) {
    if (error.code === 'auth/user-not-found') throw new HttpsError('not-found', 'This customer has no login account.');
    throw error;
  }
  // Signs the customer out of other devices.
  await admin.auth().revokeRefreshTokens(uid);
  await admin.database().ref(`users/${uid}/passwordResetRequired`).set(true);
  // Returned once to the admin to send over WhatsApp; it is never stored in the database.
  return { temporaryPassword };
});

exports.deleteCustomerAccount = onCall(async (request) => {
  await assertAdmin(request);
  const uid = await getCustomerUid(request);
  try {
    await admin.auth().deleteUser(uid);
  } catch (error) {
    if (error.code !== 'auth/user-not-found') throw error;
  }
  const phone = (await admin.database().ref(`users/${uid}/phone`).once('value')).val();
  const updates = { [`users/${uid}`]: null };
  // Free the phone number so it can be registered again.
  if (phone && (await admin.database().ref(`phones/${phone}`).once('value')).val() === uid) updates[`phones/${phone}`] = null;
  await admin.database().ref().update(updates);
  return { deleted: true };
});
