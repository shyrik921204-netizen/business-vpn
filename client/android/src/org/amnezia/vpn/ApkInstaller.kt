package org.amnezia.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import java.io.File
import org.amnezia.vpn.util.Log

private const val TAG = "ApkInstaller"
private const val UPDATE_CHANNEL_ID = "sane4ek_updates"
private const val UPDATE_NOTIFICATION_ID = 4711

// Sane4ek: installs a downloaded update APK through the system PackageInstaller.
// The first update asks the user to confirm. From Android 12 on, once the app has installed
// itself (it is the "installer of record"), later updates are installed without any dialog.
object ApkInstaller {

    fun install(context: Context, apk: File) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setSize(apk.length())
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
        }
        val sessionId = installer.createSession(params)
        try {
            installer.openSession(sessionId).use { session ->
                session.openWrite("base.apk", 0, apk.length()).use { out ->
                    apk.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
                val intent = Intent(context, ApkInstallStatusReceiver::class.java)
                var flags = PendingIntent.FLAG_UPDATE_CURRENT
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) flags = flags or PendingIntent.FLAG_MUTABLE
                val pending = PendingIntent.getBroadcast(context, sessionId, intent, flags)
                Log.d(TAG, "Commit install session $sessionId, ${apk.length()} bytes")
                session.commit(pending.intentSender)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Install session failed: $e")
            try { installer.abandonSession(sessionId) } catch (_: Exception) {}
            throw e
        }
    }

    // "Sane4ek updated — tap to open": Android does not restart an app after it updated itself
    fun showUpdatedNotification(context: Context) {
        try {
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                manager.createNotificationChannel(
                    NotificationChannel(UPDATE_CHANNEL_ID, context.getString(R.string.sane4ekUpdatesChannel),
                        NotificationManager.IMPORTANCE_DEFAULT)
                )
            }
            val open = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return
            var flags = PendingIntent.FLAG_UPDATE_CURRENT
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags = flags or PendingIntent.FLAG_IMMUTABLE
            val pending = PendingIntent.getActivity(context, 0, open, flags)
            val notification = NotificationCompat.Builder(context, UPDATE_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_amnezia_round)
                .setContentTitle(context.getString(R.string.sane4ekUpdatedTitle))
                .setContentText(context.getString(R.string.sane4ekUpdatedText))
                .setContentIntent(pending)
                .setAutoCancel(true)
                .build()
            if (NotificationManagerCompat.from(context).areNotificationsEnabled()) {
                manager.notify(UPDATE_NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Updated notification failed: $e")
        }
    }
}

class ApkInstallStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
        Log.d(TAG, "Install status $status $message")
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm: Intent? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                if (confirm != null) {
                    confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    try {
                        context.startActivity(confirm)
                    } catch (e: Exception) {
                        Log.e(TAG, "Cannot show the install dialog: $e")
                    }
                }
            }
            PackageInstaller.STATUS_SUCCESS -> {}
            PackageInstaller.STATUS_FAILURE_ABORTED -> {}
            else -> Toast.makeText(context, context.getString(R.string.sane4ekUpdateFailed) +
                (if (message.isNullOrEmpty()) "" else ": $message"), Toast.LENGTH_LONG).show()
        }
    }
}

class ApkUpdatedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            ApkInstaller.showUpdatedNotification(context)
        }
    }
}
