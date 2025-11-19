package org.telegram.messenger.partisan.voicechange;

import java.util.Map;

public interface ParametersProvider {
    double getTimeStretchFactor();
    Map<Integer, Integer> getSpectrumDistortionMap(int sampleRate);
    double getF0Shift();
    double getFormantRatio();
    boolean shiftFormantsWithHarvest();
    double getMaxFormantSpread();

    int getBadSThreshold();
    int getBadShMinThreshold();
    int getBadShMaxThreshold();

    int getBadSCutoff();
    int getBadShCutoff();

    default boolean spectrumDistortionEnabled() {
        return getSpectrumDistortionMap(48000) != null;
    }

    default boolean formantShiftingEnabled() {
        return Math.abs(getF0Shift() - 1.0) > 0.01
                || Math.abs(getFormantRatio() - 1.0) > 0.01;
    }

    default boolean badSEnabled() {
        return getBadSCutoff() > 0;
    }

    default boolean badShEnabled() {
        return getBadShCutoff() > 0;
    }
}
