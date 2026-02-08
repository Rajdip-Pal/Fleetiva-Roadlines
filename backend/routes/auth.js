const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const admin = require("firebase-admin");
const db = admin.firestore();

const router = express.Router();

/* ================= GOOGLE LOGIN ================= */
router.post("/google", async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ message: "Missing Google token" });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { email, name, uid } = decoded;

    let user = await User.findOne({ googleId: uid });

    if (!user) {
      user = await User.create({
        name,
        email,
        googleId: uid,
        role: "customer",
        authProvider: "google",
      });

      // Create Firestore user document
      await db.collection('users').doc(user._id.toString()).set({
        name: user.name,
        email: user.email,
        role: user.role,
        authProvider: user.authProvider,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        isVerified: false
      });
    }

    const accessToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ accessToken });
  } catch (err) {
    res.status(401).json({ message: "Invalid Google token" });
  }
});

/* ================= FIREBASE LOGIN/SYNC ================= */
router.post("/firebase/login", async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ message: "Firebase ID token required" });
    }

    // Verify Firebase token
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { uid, email, name, email_verified } = decoded;

    // Find or create user in MongoDB
    let user = await User.findOne({
      $or: [
        { firebaseUid: uid },
        { email: email }
      ]
    });

    if (!user) {
      user = await User.create({
        name: name || email.split('@')[0],
        email: email,
        firebaseUid: uid,
        authProvider: "firebase",
        role: "customer",
        isVerified: email_verified || false
      });

      // Create Firestore user document
      await db.collection('users').doc(user._id.toString()).set({
        name: user.name,
        email: user.email,
        role: user.role,
        authProvider: user.authProvider,
        firebaseUid: user.firebaseUid,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        isVerified: user.isVerified
      });
      console.log("✅ New Firebase user created:", user._id);
    } else {
      // Update existing user with Firebase UID if not set
      if (!user.firebaseUid) {
        user.firebaseUid = uid;
        user.authProvider = "firebase";
        user.isVerified = email_verified || user.isVerified;
        await user.save();

        // Update Firestore document
        await db.collection('users').doc(user._id.toString()).update({
          firebaseUid: user.firebaseUid,
          authProvider: user.authProvider,
          isVerified: user.isVerified,
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log("✅ Existing user updated with Firebase UID:", user._id);
      }
    }

    // Fetch user profile from Firestore
    const userDoc = await db.collection('users').doc(user._id.toString()).get();
    const userProfile = userDoc.exists ? userDoc.data() : null;

    // Generate JWT token
    const accessToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        profile: userProfile
      }
    });
  } catch (err) {
    console.error("❌ Firebase login error:", err);
    res.status(401).json({ message: "Firebase authentication failed" });
  }
});

/* ================= FIREBASE USER SYNC ================= */
router.post("/firebase/sync", require("../middleware/combinedAuth").authenticate, async (req, res) => {
  try {
    const userId = req.user.userId;

    // User should already be synced by the middleware, just return user data
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Fetch user profile from Firestore
    const userDoc = await db.collection('users').doc(user._id.toString()).get();
    const userProfile = userDoc.exists ? userDoc.data() : null;

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        profile: userProfile
      }
    });
  } catch (err) {
    console.error("❌ Firebase sync error:", err);
    res.status(500).json({ message: "User sync failed" });
  }
});

/* ================= UPDATE USER PROFILE ================= */
router.put("/profile", require("../middleware/combinedAuth").authenticate, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { name, phone, companyName } = req.body;

    // Update MongoDB user
    const user = await User.findByIdAndUpdate(
      userId,
      { name, phone, companyName },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update Firestore user document
    await db.collection('users').doc(userId.toString()).update({
      name: user.name,
      phone: user.phone,
      companyName: user.companyName,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        companyName: user.companyName,
        role: user.role
      }
    });
  } catch (err) {
    console.error("❌ Profile update error:", err);
    res.status(500).json({ message: "Profile update failed" });
  }
});

module.exports = router;
