package io.github.ginzaroot.autostart;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.system.Os;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public final class RootService extends Service {
    public static final String EXTRA_MODE = "mode";
    public static final String EXTRA_IMMEDIATE = "immediate";
    public static final String EXTRA_AUTHORIZED_KEYS = "authorizedKeys";
    public static final String MODE_ROOT_SERVER = "root-server";
    public static final String MODE_PROVISION_KEYS = "provision-keys";
    public static final String MODE_DUMP_LOG = "dump-log";

    private static final String TAG = "GinzaRoot";
    private static final String CHANNEL_ID = "ginza-root";
    private static final int NOTIFICATION_ID = 38181;
    private static final long BOOT_DELAY_MILLIS = 75_000L;
    private static final Set<String> ALLOWED_MODES = new HashSet<>(Arrays.asList(
            "target-check", "credential-smoke", "smoke", "compute-smoke", MODE_ROOT_SERVER,
            MODE_PROVISION_KEYS, MODE_DUMP_LOG));

    private final AtomicBoolean launched = new AtomicBoolean(false);
    private volatile Process rootProcess;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        startForeground(NOTIFICATION_ID, notification("Waiting to start"));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String mode = intent == null ? MODE_ROOT_SERVER : intent.getStringExtra(EXTRA_MODE);
        boolean immediate = intent != null && intent.getBooleanExtra(EXTRA_IMMEDIATE, false);

        if (mode == null) {
            mode = MODE_ROOT_SERVER;
        }
        if (!ALLOWED_MODES.contains(mode)) {
            Log.e(TAG, "Refusing unsupported mode: " + mode);
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        if (MODE_DUMP_LOG.equals(mode)) {
            Thread reader = new Thread(new Runnable() {
                @Override
                public void run() {
                    dumpRootLog(startId);
                }
            }, "ginza-log-reader");
            reader.start();
            return START_NOT_STICKY;
        }
        if (!launched.compareAndSet(false, true)) {
            Log.i(TAG, "A native process is already associated with this service instance");
            return START_NOT_STICKY;
        }

        final String selectedMode = mode;
        final String authorizedKeys = intent == null
                ? null
                : intent.getStringExtra(EXTRA_AUTHORIZED_KEYS);
        final long delay = immediate || !MODE_ROOT_SERVER.equals(mode) ? 0L : BOOT_DELAY_MILLIS;
        Thread launcher = new Thread(new Runnable() {
            @Override
            public void run() {
                if (MODE_PROVISION_KEYS.equals(selectedMode)) {
                    provisionAuthorizedKeys(authorizedKeys, startId);
                } else {
                    launch(selectedMode, delay, startId);
                }
            }
        }, "ginza-launcher");
        launcher.start();
        return START_NOT_STICKY;
    }

    private void launch(String mode, long delayMillis, int startId) {
        try {
            if (delayMillis > 0) {
                updateNotification("Waiting for boot services");
                Thread.sleep(delayMillis);
            }

            Context storage = createDeviceProtectedStorageContext();
            File files = storage.getFilesDir();
            if (!files.isDirectory() && !files.mkdirs()) {
                throw new IOException("Cannot create " + files);
            }
            String bootId = readFirstLine(new File("/proc/sys/kernel/random/boot_id"));
            File marker = new File(files, "root-attempt.boot-id");
            if (MODE_ROOT_SERVER.equals(mode) && marker.isFile()
                    && bootId.equals(readFirstLine(marker))) {
                throw new IOException("A root attempt already started during boot " + bootId);
            }
            if (MODE_ROOT_SERVER.equals(mode)) {
                writeText(marker, bootId + "\n");
            }

            File executable = new File(getApplicationInfo().nativeLibraryDir, "libginzaroot.so");
            File log = new File(files, "ginza-" + mode + ".log");
            ProcessBuilder builder;
            if (MODE_ROOT_SERVER.equals(mode)) {
                builder = new ProcessBuilder(executable.getAbsolutePath(), mode, "640");
                File dropbear = new File(getApplicationInfo().nativeLibraryDir,
                        "libdropbearmulti.so");
                builder.environment().put("GINZA_DROPBEAR", dropbear.getAbsolutePath());
                builder.environment().put("GINZA_STATE_DIR",
                        new File(files, "ssh").getAbsolutePath());
            } else {
                builder = new ProcessBuilder(executable.getAbsolutePath(), mode);
            }
            builder.redirectErrorStream(true);
            builder.redirectOutput(log);
            updateNotification("Starting " + mode);
            rootProcess = builder.start();
            updateNotification(mode + " is running");
            int result = rootProcess.waitFor();
            Log.i(TAG, mode + " exited with status " + result + "; log=" + log);
            updateNotification(mode + " exited: " + result);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            Log.e(TAG, "Launcher interrupted", error);
            updateNotification("Launcher interrupted");
        } catch (IOException | RuntimeException error) {
            Log.e(TAG, "Cannot start Ginza root", error);
            updateNotification("Start failed: " + error.getMessage());
        } finally {
            if (!MODE_ROOT_SERVER.equals(mode)) {
                stopSelf(startId);
            }
        }
    }

    private void provisionAuthorizedKeys(String encoded, int startId) {
        try {
            if (encoded == null || encoded.isEmpty()) {
                throw new IOException("No authorized keys were supplied");
            }
            byte[] keys;
            try {
                keys = Base64.decode(encoded, Base64.DEFAULT);
            } catch (IllegalArgumentException error) {
                throw new IOException("Authorized keys are not valid Base64", error);
            }
            validateAuthorizedKeys(keys);

            File files = createDeviceProtectedStorageContext().getFilesDir();
            File directory = new File(files, "ssh");
            if (!directory.isDirectory() && !directory.mkdirs()) {
                throw new IOException("Cannot create " + directory);
            }
            Os.chmod(directory.getAbsolutePath(), 0700);
            File authorizedKeys = new File(directory, "authorized_keys");
            try (FileOutputStream output = new FileOutputStream(authorizedKeys, false)) {
                output.write(keys);
                output.getFD().sync();
            }
            Os.chmod(authorizedKeys.getAbsolutePath(), 0600);
            String digest = sha256(keys);
            Log.i(TAG, "Provisioned authorized_keys sha256=" + digest);
            updateNotification("SSH keys provisioned");
        } catch (Exception error) {
            Log.e(TAG, "Cannot provision SSH keys", error);
            updateNotification("Key provisioning failed: " + error.getMessage());
        } finally {
            stopSelf(startId);
        }
    }

    private void dumpRootLog(int startId) {
        File log = new File(createDeviceProtectedStorageContext().getFilesDir(),
                "ginza-root-server.log");
        try (BufferedReader reader = new BufferedReader(new FileReader(log))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count < 4096) {
                Log.i(TAG, "native: " + line);
                count++;
            }
            Log.i(TAG, "Dumped " + count + " native log lines from " + log);
            updateNotification("Native log written to logcat");
        } catch (IOException error) {
            Log.e(TAG, "Cannot read native root log", error);
            updateNotification("Log read failed: " + error.getMessage());
        } finally {
            if (!launched.get()) {
                stopSelf(startId);
            }
        }
    }

    private static void validateAuthorizedKeys(byte[] keys) throws IOException {
        if (keys.length == 0 || keys.length > 64 * 1024) {
            throw new IOException("Authorized keys size is outside the accepted range");
        }
        String text = new String(keys, StandardCharsets.UTF_8);
        if (text.indexOf('\0') >= 0) {
            throw new IOException("Authorized keys contain a NUL byte");
        }
        int count = 0;
        for (String line : text.split("\\r?\\n")) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            if (!line.matches("(?:ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]+={0,2}(?: .*)?")) {
                throw new IOException("Unsupported authorized key line");
            }
            count++;
        }
        if (count == 0 || count > 16) {
            throw new IOException("Authorized keys must contain between 1 and 16 keys");
        }
    }

    private static String sha256(byte[] value) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder output = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            output.append(String.format("%02x", item & 0xff));
        }
        return output.toString();
    }

    private void createNotificationChannel() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Keeps the verified Ginza root process alive");
        manager.createNotificationChannel(channel);
    }

    private Notification notification(String text) {
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(text)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.notify(NOTIFICATION_ID, notification(text));
    }

    private static String readFirstLine(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line = reader.readLine();
            if (line == null || line.isEmpty()) {
                throw new IOException("No value in " + file);
            }
            return line;
        }
    }

    private static void writeText(File file, String text) throws IOException {
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(text.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public void onDestroy() {
        Process process = rootProcess;
        if (process != null && process.isAlive()) {
            Log.w(TAG, "Service stopped while native process remains alive; reboot before retrying");
        }
        super.onDestroy();
    }
}
