// login_screen.dart
// -------------------
// Entry screen shown when no Firebase session exists. Supports both auth
// methods named in the PRD: Phone Number OTP and Email/Password.

import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/material.dart';
import '../services/auth_service.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

enum _AuthMode { phone, email }

class _LoginScreenState extends State<LoginScreen> {
  _AuthMode _mode = _AuthMode.phone;
  bool _isEmailSignUp = false;
  bool _isLoading = false;
  String? _error;

  // Phone flow state
  final _phoneController = TextEditingController();
  final _otpController = TextEditingController();
  String? _verificationId;
  bool _otpSent = false;

  // Email flow state
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  @override
  void dispose() {
    _phoneController.dispose();
    _otpController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _sendOtp() async {
    if (_phoneController.text.trim().isEmpty) {
      setState(() => _error = 'Enter a phone number in +country code format.');
      return;
    }
    setState(() {
      _isLoading = true;
      _error = null;
    });

    await AuthService.instance.startPhoneVerification(
      phoneNumber: _phoneController.text.trim(),
      onCodeSent: (verificationId) {
        setState(() {
          _verificationId = verificationId;
          _otpSent = true;
          _isLoading = false;
        });
      },
      onError: (e) {
        setState(() {
          _error = e.message ?? 'Phone verification failed.';
          _isLoading = false;
        });
      },
      onAutoVerified: (_) {
        // Android auto-retrieved the OTP — authStateChanges will fire and
        // RootGate (see main.dart) navigates to the app automatically.
      },
    );
  }

  Future<void> _confirmOtp() async {
    if (_verificationId == null || _otpController.text.trim().isEmpty) return;
    setState(() {
      _isLoading = true;
      _error = null;
    });
    try {
      await AuthService.instance.verifyOtpAndSignIn(
        verificationId: _verificationId!,
        smsCode: _otpController.text.trim(),
      );
      // Success -> authStateChanges stream fires -> RootGate swaps to RootShell.
    } on FirebaseAuthException catch (e) {
      setState(() => _error = e.message ?? 'Invalid OTP.');
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _submitEmail() async {
    if (_emailController.text.trim().isEmpty || _passwordController.text.isEmpty) {
      setState(() => _error = 'Enter both email and password.');
      return;
    }
    setState(() {
      _isLoading = true;
      _error = null;
    });
    try {
      if (_isEmailSignUp) {
        await AuthService.instance.signUpWithEmail(
          email: _emailController.text.trim(),
          password: _passwordController.text,
        );
      } else {
        await AuthService.instance.signInWithEmail(
          email: _emailController.text.trim(),
          password: _passwordController.text,
        );
      }
    } on FirebaseAuthException catch (e) {
      setState(() => _error = e.message ?? 'Authentication failed.');
    } finally {
      setState(() => _isLoading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.shield_rounded, size: 72, color: Color(0xFF1B4332)),
                const SizedBox(height: 12),
                Text('PropGuard AI', style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 4),
                Text(
                  'Sign in to protect your property deals and your safety.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodyMedium,
                ),
                const SizedBox(height: 24),
                SegmentedButton<_AuthMode>(
                  segments: const [
                    ButtonSegment(value: _AuthMode.phone, label: Text('Phone OTP'), icon: Icon(Icons.sms_rounded)),
                    ButtonSegment(value: _AuthMode.email, label: Text('Email'), icon: Icon(Icons.email_rounded)),
                  ],
                  selected: {_mode},
                  onSelectionChanged: (s) => setState(() {
                    _mode = s.first;
                    _error = null;
                  }),
                ),
                const SizedBox(height: 24),
                if (_mode == _AuthMode.phone) _buildPhoneFlow() else _buildEmailFlow(),
                if (_error != null) ...[
                  const SizedBox(height: 16),
                  Text(_error!, style: const TextStyle(color: Colors.red)),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildPhoneFlow() {
    return Column(
      children: [
        TextField(
          controller: _phoneController,
          enabled: !_otpSent,
          keyboardType: TextInputType.phone,
          decoration: const InputDecoration(
            labelText: 'Phone number',
            hintText: '+919812345678',
            prefixIcon: Icon(Icons.phone_rounded),
            border: OutlineInputBorder(),
          ),
        ),
        if (_otpSent) ...[
          const SizedBox(height: 12),
          TextField(
            controller: _otpController,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: '6-digit OTP',
              prefixIcon: Icon(Icons.lock_clock_rounded),
              border: OutlineInputBorder(),
            ),
          ),
        ],
        const SizedBox(height: 16),
        FilledButton(
          onPressed: _isLoading ? null : (_otpSent ? _confirmOtp : _sendOtp),
          child: _isLoading
              ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
              : Text(_otpSent ? 'Verify & Continue' : 'Send OTP'),
        ),
      ],
    );
  }

  Widget _buildEmailFlow() {
    return Column(
      children: [
        TextField(
          controller: _emailController,
          keyboardType: TextInputType.emailAddress,
          decoration: const InputDecoration(
            labelText: 'Email',
            prefixIcon: Icon(Icons.email_rounded),
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _passwordController,
          obscureText: true,
          decoration: const InputDecoration(
            labelText: 'Password',
            prefixIcon: Icon(Icons.lock_rounded),
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 16),
        FilledButton(
          onPressed: _isLoading ? null : _submitEmail,
          child: _isLoading
              ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
              : Text(_isEmailSignUp ? 'Create Account' : 'Sign In'),
        ),
        TextButton(
          onPressed: () => setState(() => _isEmailSignUp = !_isEmailSignUp),
          child: Text(_isEmailSignUp ? 'Already have an account? Sign in' : "New here? Create an account"),
        ),
      ],
    );
  }
}
