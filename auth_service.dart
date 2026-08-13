// auth_service.dart
// -------------------
// Wraps Firebase Auth per the PRD:
//   "User Sign-Up & Login: Handled via Firebase Auth using Phone Number OTP
//    or Email/Password. Token Passing: the Flutter client retrieves a
//    short-lived JWT ID Token and appends it to all HTTP request headers."
//
// Every authenticated API call in api_service.dart pulls its Bearer token
// from `AuthService.instance.idToken`.

import 'dart:async';
import 'package:firebase_auth/firebase_auth.dart';

class AuthService {
  AuthService._();
  static final AuthService instance = AuthService._();

  final FirebaseAuth _firebaseAuth = FirebaseAuth.instance;

  Stream<User?> get authStateChanges => _firebaseAuth.authStateChanges();
  User? get currentUser => _firebaseAuth.currentUser;
  bool get isSignedIn => _firebaseAuth.currentUser != null;

  /// Returns a fresh Firebase ID token (JWT) for the current session,
  /// refreshing it if it's close to expiry. Every backend request attaches
  /// this as `Authorization: Bearer <token>`.
  Future<String?> get idToken async {
    final user = _firebaseAuth.currentUser;
    if (user == null) return null;
    return user.getIdToken(); // SDK auto-refreshes if near expiry.
  }

  // ------------------------------------------------------------------
  // Email / Password flow
  // ------------------------------------------------------------------

  Future<UserCredential> signUpWithEmail({
    required String email,
    required String password,
  }) {
    return _firebaseAuth.createUserWithEmailAndPassword(email: email, password: password);
  }

  Future<UserCredential> signInWithEmail({
    required String email,
    required String password,
  }) {
    return _firebaseAuth.signInWithEmailAndPassword(email: email, password: password);
  }

  Future<void> sendPasswordResetEmail(String email) {
    return _firebaseAuth.sendPasswordResetEmail(email: email);
  }

  // ------------------------------------------------------------------
  // Phone OTP flow
  // ------------------------------------------------------------------

  /// Starts phone verification. `onCodeSent` fires once Firebase has
  /// dispatched the SMS OTP; the resulting `verificationId` is then passed
  /// into `verifyOtpAndSignIn` alongside the 6-digit code the user types in.
  Future<void> startPhoneVerification({
    required String phoneNumber, // E.164 format, e.g. +919812345678
    required void Function(String verificationId) onCodeSent,
    required void Function(FirebaseAuthException error) onError,
    void Function(UserCredential credential)? onAutoVerified,
  }) async {
    await _firebaseAuth.verifyPhoneNumber(
      phoneNumber: phoneNumber,
      timeout: const Duration(seconds: 60),
      verificationCompleted: (PhoneAuthCredential credential) async {
        // Android may auto-retrieve the OTP from SMS without user input.
        final result = await _firebaseAuth.signInWithCredential(credential);
        onAutoVerified?.call(result);
      },
      verificationFailed: onError,
      codeSent: (String verificationId, int? resendToken) {
        onCodeSent(verificationId);
      },
      codeAutoRetrievalTimeout: (String verificationId) {
        // No-op: if the user hasn't submitted the code by timeout, they
        // simply enter it manually via verifyOtpAndSignIn below.
      },
    );
  }

  Future<UserCredential> verifyOtpAndSignIn({
    required String verificationId,
    required String smsCode,
  }) {
    final credential = PhoneAuthProvider.credential(
      verificationId: verificationId,
      smsCode: smsCode,
    );
    return _firebaseAuth.signInWithCredential(credential);
  }

  // ------------------------------------------------------------------

  Future<void> signOut() => _firebaseAuth.signOut();
}
