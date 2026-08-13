package com.propguard.app.interceptor

import android.app.Notification
import android.content.SharedPreferences
import android.content.Context
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.google.android.gms.tasks.Tasks
import com.google.firebase.auth.FirebaseAuth
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * WhatsAppSpamListener
 * ---------------------
 * Extends Android's NotificationListenerService to intercept incoming
 * WhatsApp (and generic SMS) notification banners, run a fast on-device
 * regex/keyword filter, and asynchronously forward anything suspicious
 * (or everything, depending on config) to the PropGuard backend's
 * /api/v1/interceptor/scan endpoint for deeper Nemotron analysis.
 *
 * IMPORTANT (privacy): We intentionally do NOT read full chat history or
 * contact details — only the notification's title/text as delivered by
 * the OS, which is the same content already shown on the lock screen.
 * The user must explicitly grant "Notification Access" in Android
 * Settings for this service to receive any callbacks.
 *
 * IMPORTANT (auth): the backend requires a valid Firebase Bearer JWT on
 * every request (see app/auth.py). This service is a background
 * NotificationListenerService with no Activity/UI, so it fetches a fresh
 * ID token directly from FirebaseAuth.getInstance().currentUser — the same
 * signed-in session the Flutter UI is using — rather than storing any
 * credential of its own.
 */
class WhatsAppSpamListener : NotificationListenerService() {

    companion object {
        private const val TAG = "WhatsAppSpamListener"
        private const val WHATSAPP_PACKAGE = "com.whatsapp"
        private const val WHATSAPP_BUSINESS_PACKAGE = "com.whatsapp.w4b"
        private const val SMS_PACKAGE_PREFIX = "com.google.android.apps.messaging"

        // Local, on-device first-pass filter — mirrors keyword_rules.py on the
        // backend so we get an instant signal before the network round-trip.
        private val SCAM_KEYWORDS = listOf(
            "guaranteed return",
            "guaranteed returns",
            "urgent plot booking",
            "transfer advance",
            "advance payment required",
            "limited time offer",
            "book now pay later",
            "no documentation required",
            "double your investment",
            "risk free investment",
            "token amount",
            "pay to block",
            "confirm booking with token"
        )
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO)

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private lateinit var prefs: SharedPreferences

    override fun onCreate() {
        super.onCreate()
        prefs = getSharedPreferences("propguard_prefs", Context.MODE_PRIVATE)
        Log.i(TAG, "WhatsAppSpamListener created.")
    }

    /**
     * Called by the OS whenever any app posts a notification. We filter
     * down to WhatsApp / SMS packages only and ignore everything else
     * (system, other apps) to minimize what we touch.
     */
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        super.onNotificationPosted(sbn)

        val packageName = sbn.packageName
        val isRelevant = packageName == WHATSAPP_PACKAGE ||
            packageName == WHATSAPP_BUSINESS_PACKAGE ||
            packageName.startsWith(SMS_PACKAGE_PREFIX)

        if (!isRelevant) return

        val extras = sbn.notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""

        if (text.isBlank()) return

        val matchedKeywords = findMatchedKeywords(text)
        val localRuleMatched = matchedKeywords.isNotEmpty()

        Log.d(TAG, "Notification from $packageName — localRuleMatched=$localRuleMatched")

        // Forward to backend regardless of local match — Nemotron catches
        // scams the keyword list misses (obfuscated spelling, new tactics).
        serviceScope.launch {
            dispatchToBackend(
                sourceApp = packageName,
                senderLabel = title,
                messageText = text,
                matchedKeywords = matchedKeywords
            )
        }

        // Immediate local alert for high-confidence keyword hits, without
        // waiting on the network — the backend result can still upgrade
        // this later via a push notification / in-app banner.
        if (localRuleMatched) {
            LocalAlertDispatcher.showImmediateWarning(applicationContext, title, matchedKeywords)
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        super.onNotificationRemoved(sbn)
        // No-op: we don't need to react to notification dismissal.
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        Log.i(TAG, "Notification listener connected — PropGuard Shield is ACTIVE.")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        Log.w(TAG, "Notification listener disconnected — PropGuard Shield is INACTIVE.")
        // Consider surfacing a persistent app notification prompting the
        // user to re-enable Notification Access in Settings.
    }

    private fun findMatchedKeywords(text: String): List<String> {
        val lower = text.lowercase()
        return SCAM_KEYWORDS.filter { lower.contains(it) }
    }

    /**
     * POSTs the intercepted message to the FastAPI backend:
     *   POST /api/v1/interceptor/scan
     * Body matches InterceptorScanRequest in schemas.py. Identity comes
     * entirely from the Authorization: Bearer <Firebase JWT> header — the
     * backend derives user_id from the verified token, never from the body.
     */
    private fun dispatchToBackend(
        sourceApp: String,
        senderLabel: String,
        messageText: String,
        matchedKeywords: List<String>
    ) {
        val firebaseUser = FirebaseAuth.getInstance().currentUser
        if (firebaseUser == null) {
            Log.w(TAG, "No signed-in PropGuard session — skipping backend scan.")
            return
        }

        val idToken: String = try {
            // Blocking call is safe here — we're already on Dispatchers.IO,
            // off both the main thread and the NotificationListenerService's
            // binder thread. `false` reuses the cached token if still fresh.
            Tasks.await(firebaseUser.getIdToken(false)).token ?: run {
                Log.w(TAG, "Firebase returned a null ID token — skipping scan.")
                return
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch Firebase ID token", e)
            return
        }

        val baseUrl = prefs.getString("propguard_api_base_url", ApiConfig.DEFAULT_BASE_URL)

        val json = JSONObject().apply {
            put("source_app", sourceApp)
            put("sender_label", senderLabel)
            put("message_text", messageText)
        }

        val mediaType = "application/json; charset=utf-8".toMediaType()
        val requestBody = json.toString().toRequestBody(mediaType)

        val request = Request.Builder()
            .url("$baseUrl/api/v1/interceptor/scan")
            .post(requestBody)
            .addHeader("Content-Type", "application/json")
            .addHeader("Authorization", "Bearer $idToken")
            .build()

        try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "Backend scan failed: HTTP ${response.code}")
                    return
                }
                val bodyStr = response.body?.string() ?: return
                val result = JSONObject(bodyStr)
                val shouldAlert = result.optBoolean("should_alert_user", false)
                if (shouldAlert) {
                    LocalAlertDispatcher.showBackendVerdict(applicationContext, result)
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "Network error dispatching to PropGuard backend", e)
        }
    }
}

/** Base URL default; override via SharedPreferences("propguard_prefs") key "propguard_api_base_url". */
object ApiConfig {
    const val DEFAULT_BASE_URL = "https://api.propguard.example.com"
}
