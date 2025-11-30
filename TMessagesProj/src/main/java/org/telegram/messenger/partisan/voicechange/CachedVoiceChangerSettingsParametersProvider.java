package org.telegram.messenger.partisan.voicechange;

import com.google.common.base.Strings;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

public class CachedVoiceChangerSettingsParametersProvider implements ParametersProvider {
    private final double timeStretchFactor;
    private final String spectrumDistortionParams;
    private final double f0Shift;
    private final double formantRatio;
    private final boolean formantShiftingHarvest;
    private final double maxFormantSpread;
    private final int badSThreshold;
    private final int badShMinThreshold;
    private final int badShMaxThreshold;
    private final int badSCutoff;
    private final int badShCutoff;
    private final boolean useOldWindowRestore;

    public CachedVoiceChangerSettingsParametersProvider() {
        timeStretchFactor = 1.0;
        spectrumDistortionParams = VoiceChangeSettings.spectrumDistortionParams.get().orElse("");
        f0Shift = VoiceChangeSettings.f0Shift.get().orElse(1.0f);
        formantRatio = VoiceChangeSettings.formantRatio.get().orElse(1.0f);
        formantShiftingHarvest = VoiceChangeSettings.formantShiftingHarvest.get().orElse(false);
        maxFormantSpread = VoiceChangeSettings.maxFormantSpread.get().orElse(0.0f);
        badSThreshold = VoiceChangeSettings.badSThreshold.get().orElse(4500);
        badShMinThreshold = VoiceChangeSettings.badShMinThreshold.get().orElse(2000);
        badShMaxThreshold = VoiceChangeSettings.badShMaxThreshold.get().orElse(4500);
        badSCutoff = VoiceChangeSettings.badSCutoff.get().orElse(0);
        badShCutoff = VoiceChangeSettings.badShCutoff.get().orElse(0);
        useOldWindowRestore = VoiceChangeSettings.useOldWindowRestore.get().orElse(true);
    }

    @Override
    public double getTimeStretchFactor() {
        return timeStretchFactor;
    }

    @Override
    public Map<Integer, Integer> getSpectrumDistortionMap(int sampleRate) {
        Map<Integer, Integer> distortionMap = accumulateDistortionParams(
                spectrumDistortionParams,
                new HashMap<>(),
                (map, distortionParts) -> {
                    int fromHz = Integer.parseInt(distortionParts[0]);
                    int toHz = Integer.parseInt(distortionParts[1]);
                    int fromIndex = (fromHz * Constants.defaultBufferSize) / sampleRate;
                    int toIndex = (toHz * Constants.defaultBufferSize) / sampleRate;
                    map.put(fromIndex, toIndex);
                });
        return distortionMap != null && !distortionMap.isEmpty() ? distortionMap : null;
    }

    private <T> T accumulateDistortionParams(String params, T collection, BiConsumer<T, String[]> accumulationFunction) {
        if (Strings.isNullOrEmpty(params)) {
            return null;
        }
        try {
            String[] distortionStrings = params.split(",");
            for (String distortionString : distortionStrings) {
                if (Strings.isNullOrEmpty(distortionString)) {
                    return null;
                }
                String[] distortionParts = distortionString.split(":");
                if (distortionParts.length != 2) {
                    return null;
                }
                accumulationFunction.accept(collection, distortionParts);
            }
            return collection;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public double getF0Shift() {
        return f0Shift;
    }

    @Override
    public double getFormantRatio() {
        return formantRatio;
    }

    @Override
    public boolean shiftFormantsWithHarvest() {
        return formantShiftingHarvest;
    }

    @Override
    public double getMaxFormantSpread() {
        return maxFormantSpread;
    }

    @Override
    public int getBadSThreshold() {
        return badSThreshold;
    }

    @Override
    public int getBadShMinThreshold() {
        return badShMinThreshold;
    }

    @Override
    public int getBadShMaxThreshold() {
        return badShMaxThreshold;
    }

    @Override
    public int getBadSCutoff() {
        return badSCutoff;
    }

    @Override
    public int getBadShCutoff() {
        return badShCutoff;
    }

    @Override
    public boolean useOldWindowRestore() {
        return useOldWindowRestore;
    }
}
