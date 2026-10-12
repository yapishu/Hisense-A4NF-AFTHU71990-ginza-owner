package io.github.ginzaroot.autostart;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (!Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_BOOT_COMPLETED.equals(action)) {
            return;
        }

        Intent service = new Intent(context, RootService.class);
        service.putExtra(RootService.EXTRA_MODE, RootService.MODE_ROOT_SERVER);
        context.startForegroundService(service);
    }
}
