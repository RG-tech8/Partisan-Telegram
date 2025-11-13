package org.telegram.messenger.partisan.voicechange;

import com.google.common.base.Strings;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

public class TesterSettingsParametersProvider implements ParametersProvider {
    @Override
    public double getTimeStretchFactor() {
        return 1.0;
    }

    @Override
    public Map<Integer, Integer> getSpectrumDistortionMap(int sampleRate) {
        Map<Integer, Integer> distortionMap = accumulateDistortionParams(
                VoiceChangeSettings.spectrumDistortionParams.get().orElse(""),
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
        return VoiceChangeSettings.f0Shift.get().orElse(1.0f);
    }

    @Override
    public double getFormantRatio() {
        return VoiceChangeSettings.formantRatio.get().orElse(1.0f);
    }

    @Override
    public boolean shiftFormantsWithHarvest() {
        return VoiceChangeSettings.formantShiftingHarvest.get().orElse(false);
    }

    public int getBadSThreshold() {
        return VoiceChangeSettings.badSThreshold.get().orElse(4500);
    }

    public int getBadShMinThreshold() {
        return VoiceChangeSettings.badShMinThreshold.get().orElse(2000);
    }

    public int getBadShMaxThreshold() {
        return VoiceChangeSettings.badShMaxThreshold.get().orElse(4500);
    }

    public int getBadSCutoff() {
        return VoiceChangeSettings.badSCutoff.get().orElse(0);
    }

    public int getBadShCutoff() {
        return VoiceChangeSettings.badShCutoff.get().orElse(0);
    }
}
