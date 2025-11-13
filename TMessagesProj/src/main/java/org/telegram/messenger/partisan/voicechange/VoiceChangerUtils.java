package org.telegram.messenger.partisan.voicechange;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.NotificationCenter;
import org.telegram.messenger.UserConfig;
import org.telegram.messenger.fakepasscode.FakePasscodeUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class VoiceChangerUtils {
    private static final Map<VoiceChanger, VoiceChangeType> runningVoiceChangers = new HashMap<>();

    public static VoiceChanger createVoiceChangerIfNeeded(int accountNum, VoiceChangeType type, int sampleRate) {
        return genericCreateVoiceChangerIfNeeded(
                accountNum,
                type,
                () -> new VoiceChanger(new TesterSettingsParametersProvider(), sampleRate)
        );
    }

    public static RealTimeVoiceChanger createRealTimeVoiceChangerIfNeeded(int accountNum, VoiceChangeType type, int sampleRate) {
        return genericCreateVoiceChangerIfNeeded(
                accountNum,
                type,
                () -> new RealTimeVoiceChanger(new TesterSettingsParametersProvider(), sampleRate)
        );
    }

    private static <T extends VoiceChanger> T genericCreateVoiceChangerIfNeeded(int accountNum, VoiceChangeType type, Supplier<T> constructor) {
        if (!needChangeVoice(accountNum, type)) {
            return null;
        }
        final T voiceChanger = constructor.get();
        runningVoiceChangers.put(voiceChanger, type);
        AndroidUtilities.runOnUIThread(() -> NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.voiceChangingStateChanged));
        voiceChanger.setStopCallback(() -> {
            runningVoiceChangers.remove(voiceChanger);
            AndroidUtilities.runOnUIThread(() -> NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.voiceChangingStateChanged));
        });
        return voiceChanger;
    }

    public static boolean needChangeVoice(int accountNum, VoiceChangeType type) {
        return voiceChangeEnabled(accountNum, type) && anyParameterSet();
    }

    private static boolean voiceChangeEnabled(int accountNum, VoiceChangeType type) {
        if (FakePasscodeUtils.isFakePasscodeActivated() && !VoiceChangeSettings.voiceChangeWorksWithFakePasscode.get().orElse(true)) {
            return false;
        }
        if (!VoiceChangeSettings.voiceChangeEnabled.get().orElse(false)) {
            return false;
        }
        if (type != null && !VoiceChangeSettings.isVoiceChangeTypeEnabled(type)) {
            return false;
        }
        return UserConfig.getInstance(accountNum).voiceChangeEnabledForAccount;
    }

    private static boolean anyParameterSet() {
        ParametersProvider parametersProvider = new TesterSettingsParametersProvider();
        return parametersProvider.spectrumDistortionEnabled()
                || parametersProvider.formantShiftingEnabled()
                || parametersProvider.badSEnabled()
                || parametersProvider.badShEnabled();
    }

    public static boolean needShowVoiceChangeNotification(VoiceChangeType type) {
        return isAnyVoiceChangerRunning(type) && VoiceChangeSettings.showVoiceChangedNotification.get().orElse(true);
    }

    private static boolean isAnyVoiceChangerRunning(VoiceChangeType type) {
        return runningVoiceChangers.containsValue(type);
    }
}
